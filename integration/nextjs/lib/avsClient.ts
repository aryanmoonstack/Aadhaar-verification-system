/**
 * AVS client — HMAC signing and transport. SERVER ONLY.
 *
 * ⛔⛔ THIS FILE MUST NEVER BE IMPORTED BY A CLIENT COMPONENT.
 *
 *    It reads `process.env.AVS_SECRET`. In Next.js, only variables prefixed
 *    `NEXT_PUBLIC_` are inlined into the browser bundle — so a plain
 *    `AVS_SECRET` stays on the server. That prefix is the entire difference
 *    between a server secret and a public one.
 *
 *    ⚠ Never name it `NEXT_PUBLIC_AVS_SECRET`. Anything with that prefix is
 *      compiled into JavaScript the browser downloads, and a signing key
 *      published to every visitor lets anyone submit jobs as your tenant.
 *
 *    The `import 'server-only'` below turns a mistaken client import into a
 *    BUILD failure rather than a silent leak discovered in production.
 *
 * ★ WHY THE MULTIPART BODY IS BUILT BY HAND
 *
 *   The signature covers the RAW REQUEST BODY — the exact bytes on the wire.
 *
 *   Passing a `FormData` to `fetch` lets undici generate the body itself, with
 *   its own boundary chosen at send time. You would sign one sequence of bytes
 *   and transmit a different one. Every request then fails with 401 while the
 *   secrets are perfectly correct, which is a genuinely nasty afternoon: the
 *   error says "authentication failed" and the credentials are not the problem.
 *
 *   So the body is assembled here as a Buffer, signed, and sent as that exact
 *   Buffer. The Java client does the same thing for the same reason.
 */

import 'server-only';

import { randomUUID } from 'node:crypto';

import { buildMultipart, signedHeaders, type FilePart } from './avsSignature';

export interface AvsDecision {
  /**
   * ⛔ Carried in the BODY. NOT the HTTP status of the call.
   * 200 approved · 422 retry · 202 review.
   */
  status_code: number;
  status: 'APPROVED' | 'RETRY' | 'REVIEW';
  /** ⛔ Display verbatim. Worded to never accuse anyone of forgery. */
  message: string;
  /** Independent of `status` — TAMPERED is RETRY *and* needs_review. */
  needs_review: boolean;
  verdict: string;
  signature_valid: boolean;
}

export interface AvsJobStatus {
  job_id: string;
  /** ⚠ Job lifecycle — 'PENDING' | 'DONE'. Not the verification outcome. */
  status: string;
  decision: AvsDecision | null;

  /**
   * The full result. ⛔ Contains identity and address — never forward it to a
   * browser. Read here only for the per-side error codes.
   */
  result?: {
    sides?: Array<{ error?: string | null }>;
  } | null;
}

/** Ingest codes meaning "this PDF is locked and we do not have the key". */
const PASSWORD_ERRORS = new Set(['PDF_PASSWORD_REQUIRED', 'PDF_PASSWORD_INCORRECT']);

/**
 * Did this fail purely because the PDF is locked?
 *
 * ★ Why the distinction is worth extracting. Both a locked PDF and a blurry
 *   photo arrive as `RETRY` with `UNREADABLE`, and the generic message tells
 *   the employee to take a clearer picture. For a locked PDF that advice is a
 *   dead end — the file is perfect, we simply cannot open it. They need a
 *   password box, not photography tips.
 */
export function needsPassword(status: AvsJobStatus): boolean {
  const sides = status.result?.sides ?? [];
  return sides.some((side) => side.error != null && PASSWORD_ERRORS.has(side.error));
}

function baseUrl(): string {
  const url = process.env.AVS_URL;
  if (!url) throw new Error('AVS_URL is not set');
  return url.replace(/\/+$/, '');
}

function secret(): string {
  const value = process.env.AVS_SECRET;
  if (!value) throw new Error('AVS_SECRET is not set');

  // ⚠ The Python and Java services both refuse to start on a short or
  //   placeholder secret. Failing here too means the mistake surfaces in your
  //   own logs rather than as an unexplained 401 from someone else's service.
  if (value.length < 32) {
    throw new Error(`AVS_SECRET is ${value.length} characters; minimum is 32`);
  }
  return value;
}

function sign(body: Buffer): Record<string, string> {
  return signedHeaders(secret(), process.env.AVS_TENANT_ID ?? 'm-one-prod', body);
}

/**
 * Turn browser `File` objects into the byte parts the signer needs.
 *
 * ⚠ The declared content type is a hint only. AVS re-detects from magic bytes
 *   and ignores what we claim — a PDF renamed `.jpg` is still handled as a PDF.
 *   Sending something plausible keeps logs readable; nothing depends on it.
 */
async function toParts(files: readonly { field: string; file: File }[]): Promise<FilePart[]> {
  return Promise.all(
    files.map(async ({ field, file }) => ({
      field,
      filename: file.name || field,
      contentType: file.type || 'application/octet-stream',
      data: Buffer.from(await file.arrayBuffer()),
    })),
  );
}

export interface SubmitInput {
  front: File;
  /** Omit for a PDF — its pages already carry both faces. CONTRACTS.md §11. */
  back?: File | null;
  /** For an encrypted PDF. Never logged, never stored, never echoed back. */
  password?: string | null;
  jobId?: string;
  requestId?: string;
}

export async function submit(input: SubmitInput): Promise<{ jobId: string }> {
  const chosen = [{ field: 'front', file: input.front }];
  if (input.back) chosen.push({ field: 'back', file: input.back });

  const { body, contentType } = buildMultipart(await toParts(chosen), {
    job_id: input.jobId,
    password: input.password ?? undefined,
  });

  const response = await fetch(`${baseUrl()}/v1/verify/upload`, {
    method: 'POST',
    // ⛔ The exact Buffer that was signed. Do not swap this for a FormData.
    body: body as unknown as BodyInit,
    headers: {
      'Content-Type': contentType,
      'Content-Length': String(body.length),
      'X-Request-ID': input.requestId ?? randomUUID(),
      ...sign(body),
    },
  });

  if (!response.ok) {
    // ⚠ Upstream detail is operational information the employee cannot act on,
    //   and a 401 here would name our own misconfiguration. Log it, do not
    //   forward it.
    const detail = await response.text().catch(() => '');
    console.error('avs.submit.failed', response.status, detail.slice(0, 500));
    throw new AvsUnavailable(response.status);
  }

  const parsed = (await response.json()) as { job_id: string };
  return { jobId: parsed.job_id };
}

export async function poll(jobId: string): Promise<AvsJobStatus> {
  // ⚠ A GET has no body, so the canonical string ends at the final dot:
  //   `timestamp.nonce.` — an empty Buffer, not a skipped component.
  const empty = Buffer.alloc(0);

  const response = await fetch(`${baseUrl()}/v1/verify/${encodeURIComponent(jobId)}`, {
    method: 'GET',
    headers: sign(empty),
    cache: 'no-store',
  });

  if (response.status === 404) throw new AvsJobNotFound(jobId);
  if (!response.ok) {
    console.error('avs.poll.failed', response.status);
    throw new AvsUnavailable(response.status);
  }

  return (await response.json()) as AvsJobStatus;
}

export class AvsUnavailable extends Error {
  constructor(readonly upstreamStatus: number) {
    super(`AVS returned ${upstreamStatus}`);
  }
}

export class AvsJobNotFound extends Error {
  constructor(readonly jobId: string) {
    super(`unknown job ${jobId}`);
  }
}
