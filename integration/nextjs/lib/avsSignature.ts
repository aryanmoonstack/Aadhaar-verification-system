/**
 * AVS request signing — the pure half. Mirrors `AvsSignature.java`.
 *
 * ⚠ Deliberately separate from `avsClient.ts`, which reads the environment and
 *   is marked `server-only`. Everything here is a pure function over its
 *   arguments, so it can be unit-tested — and this is the code most worth
 *   testing, because getting it wrong produces a 401 that looks like a
 *   credential problem when the credentials are fine.
 *
 * Verified byte-for-byte against the running Python service across six shared
 * vectors — see `__tests__/avsSignature.test.ts`.
 */

import { createHmac, randomBytes } from 'node:crypto';

/** Header names. Part of the contract; `avs.security` reads exactly these. */
export const HEADER_TENANT = 'X-AVS-Tenant';
export const HEADER_SIGNATURE = 'X-AVS-Signature';
export const HEADER_TIMESTAMP = 'X-AVS-Timestamp';
export const HEADER_NONCE = 'X-AVS-Nonce';

/**
 * The canonical string: `timestamp + "." + nonce + "." + body`.
 *
 * ⛔ THE DOT SEPARATORS ARE LOAD-BEARING.
 *
 *    Concatenate the parts without them and ("12", "3", body) hashes
 *    identically to ("1", "23", body). An attacker could then shift bytes
 *    between the timestamp and the nonce while keeping the signature valid —
 *    which is a replay window, not a curiosity. The dots are not formatting.
 *
 * ⚠ Ascii for the prefix, raw bytes for the body. The body may be binary — a
 *   JPEG or a PDF — so it is concatenated as bytes and never decoded to a
 *   string. Passing it through a UTF-8 round trip would corrupt it silently and
 *   only for some files, which is the worst kind of bug to chase.
 */
export function canonicalMessage(timestamp: string, nonce: string, body: Buffer): Buffer {
  return Buffer.concat([Buffer.from(`${timestamp}.${nonce}.`, 'ascii'), body]);
}

export function signature(secret: string, timestamp: string, nonce: string, body: Buffer): string {
  return createHmac('sha256', secret).update(canonicalMessage(timestamp, nonce, body)).digest('hex');
}

export interface SignedHeaders {
  [header: string]: string;
}

export function signedHeaders(
  secret: string,
  tenantId: string,
  body: Buffer,
  now: () => number = Date.now,
): SignedHeaders {
  const timestamp = Math.floor(now() / 1000).toString();
  // ⛔ Single-use. AVS rejects a replayed nonce, so this must be fresh per
  //    request — reusing one across a retry turns a transient failure into a
  //    permanent 401.
  const nonce = randomBytes(16).toString('hex');

  return {
    [HEADER_TENANT]: tenantId,
    [HEADER_TIMESTAMP]: timestamp,
    [HEADER_NONCE]: nonce,
    [HEADER_SIGNATURE]: signature(secret, timestamp, nonce, body),
  };
}

/** A quoted-string value safe for a Content-Disposition header. */
function quote(value: string): string {
  return value.replace(/[\r\n"]/g, '_');
}

export interface FilePart {
  readonly field: string;
  readonly filename: string;
  readonly contentType: string;
  readonly data: Buffer;
}

export interface Multipart {
  readonly body: Buffer;
  readonly contentType: string;
}

/**
 * Assemble a multipart body by hand, so the bytes signed are the bytes sent.
 *
 * ⛔ THIS IS WHY THE FUNCTION EXISTS AT ALL.
 *
 *    Handing a `FormData` to `fetch` lets undici generate the body itself, with
 *    a boundary it picks at send time. You sign one sequence of bytes and
 *    transmit a different one, and every request fails with 401 while the
 *    secret is perfectly correct.
 *
 *    Measured against a live service with authentication on:
 *        FormData (regenerated body)  -> HTTP 401
 *        hand-built Buffer            -> HTTP 202
 *
 *    The Java client builds its multipart by hand for exactly this reason.
 *
 * ⚠ The returned `contentType` carries the boundary and MUST be used as the
 *   header. A mismatch makes the server parse a body with no parts in it,
 *   surfacing as a puzzling 422 rather than an obvious parse error.
 */
export function buildMultipart(
  files: readonly FilePart[],
  fields: Readonly<Record<string, string | undefined | null>> = {},
): Multipart {
  const boundary = `----avs${randomBytes(16).toString('hex')}`;
  const chunks: Buffer[] = [];

  for (const [name, value] of Object.entries(fields)) {
    if (value === undefined || value === null || value === '') continue;
    chunks.push(
      Buffer.from(
        `--${boundary}\r\n` +
          `Content-Disposition: form-data; name="${quote(name)}"\r\n\r\n` +
          `${value}\r\n`,
        'utf8',
      ),
    );
  }

  for (const part of files) {
    chunks.push(
      Buffer.from(
        `--${boundary}\r\n` +
          `Content-Disposition: form-data; name="${quote(part.field)}"; ` +
          `filename="${quote(part.filename)}"\r\n` +
          `Content-Type: ${part.contentType}\r\n\r\n`,
        'utf8',
      ),
    );
    chunks.push(part.data);
    chunks.push(Buffer.from('\r\n', 'utf8'));
  }

  chunks.push(Buffer.from(`--${boundary}--\r\n`, 'utf8'));

  return {
    body: Buffer.concat(chunks),
    contentType: `multipart/form-data; boundary=${boundary}`,
  };
}
