/**
 * Corrected replacement for the Aadhaar functions in `employees.api.ts`.
 *
 * ⛔ WHY THE PREVIOUS VERSION APPROVED EVERYTHING
 *
 *    `/v1/verify/upload` answers **202 Accepted** with `{job_id, status:
 *    "PENDING"}`. That is a receipt for queued work, not a result — AVS has not
 *    read a single pixel yet.
 *
 *    The old code did:
 *
 *        success: response.ok && (... || !!data.job_id)
 *
 *    `job_id` is always present on a 202, so `success` was always true and the
 *    verdict was always "VERIFIED". A forged card, a photo of a cat, a blank
 *    page — all approved, because the only thing being tested was whether the
 *    upload arrived.
 *
 *    Verification is ASYNCHRONOUS. Submit, then POLL. The verdict exists only
 *    after `status === "DONE"`.
 *
 * ⛔ AND WHY IT COULD NEVER HAVE WORKED ANYWAY
 *
 *    It called AVS directly from the browser. Every `/v1/` route requires an
 *    HMAC signature over the raw request body, and a browser cannot hold the
 *    signing key — anything shipped to a client is public. Hence the
 *    "missing authentication headers" 401.
 *
 *    These functions call `/api/aadhaar/verify`, a same-origin Next.js route
 *    handler that runs in Node, holds `AVS_SECRET`, signs, and forwards.
 */

/** ⚠ Mirrors the `decision` block AVS computes. Do not re-derive these. */
export interface IAadhaarVerifyResponse {
  /** True only for a verified card with a valid signature. */
  success: boolean;
  /**
   * ⛔ APPROVED | RETRY | REVIEW. There is deliberately no REJECTED.
   *
   *    Nothing is ever auto-rejected. A genuine card photographed badly is
   *    indistinguishable from a forgery to any automated check, which is
   *    precisely why no automated check may call it one. On the measured
   *    corpus roughly 70% of unguided photos failed to decode — a REJECTED
   *    verdict would have accused most of those employees of fraud.
   */
  status: 'APPROVED' | 'RETRY' | 'REVIEW' | 'PENDING' | 'ERROR';
  /** The underlying verdict, unabridged. One of exactly nine. */
  verdict: string;
  /** ⛔ Display verbatim. Never substitute your own wording. */
  message: string;
  /** Whether an HR reviewer should look. Independent of `status`. */
  needsReview: boolean;
  /** True when a locked PDF needs a password from the employee. */
  needsPassword: boolean;
  /** Ask the employee for the PDF password using THIS text. */
  passwordPrompt?: string;
}

/** How long to wait for a verdict. A card that decodes settles in 1-3 s. */
const POLL_INTERVAL_MS = 1000;
const POLL_ATTEMPTS = 120;

const SUBMIT_URL = '/api/aadhaar/verify';

/**
 * ⛔ RELATIVE, and it must stay relative.
 *
 *    Same-origin means the session cookie travels and the signing happens on
 *    our server. Reintroducing `NEXT_PUBLIC_AVS_URL` here would put the browser
 *    back in front of AVS, where it cannot authenticate.
 */
async function submitAndAwait(form: FormData): Promise<IAadhaarVerifyResponse> {
  const submission = await fetch(SUBMIT_URL, {
    method: 'POST',
    body: form,
    credentials: 'include',
  });

  const accepted = await submission.json().catch(() => ({}));

  if (!submission.ok || !accepted.jobId) {
    return {
      success: false,
      status: 'ERROR',
      verdict: 'ERROR',
      // The route already phrases its errors for an employee to read.
      message:
        typeof accepted.error === 'string'
          ? accepted.error
          : 'We could not start the check just now. Please try again shortly.',
      needsReview: false,
      needsPassword: false,
    };
  }

  // ★ THE PART THAT WAS MISSING. A 202 is a receipt; the verdict comes later.
  for (let attempt = 0; attempt < POLL_ATTEMPTS; attempt++) {
    const poll = await fetch(`${SUBMIT_URL}/${encodeURIComponent(accepted.jobId)}`, {
      cache: 'no-store',
      credentials: 'include',
    });
    const body = await poll.json().catch(() => ({}));

    // The PDF is locked and we do not have the key. NOT a failure — the
    // document may be perfectly good.
    if (body.needsPassword) {
      return {
        success: false,
        status: 'RETRY',
        verdict: 'PENDING',
        message: body.passwordPrompt ?? 'Please enter the password for this PDF.',
        needsReview: false,
        needsPassword: true,
        passwordPrompt: body.passwordPrompt,
      };
    }

    if (body.decision) {
      const decision = body.decision;
      return {
        // ⛔ THE ONLY CORRECT APPROVAL TEST. Both halves are required: a
        //    mislabelling bug upstream must not be able to approve a document
        //    with no signature behind it.
        success: decision.verdict === 'VERIFIED' && decision.signature_valid === true,
        status: decision.status,
        verdict: decision.verdict,
        // ⛔ Verbatim. CONTRACTS.md §1 — worded so it never accuses anyone, and
        //    the word "fake" must not appear in employee-facing text.
        message: decision.message,
        needsReview: decision.needs_review === true,
        needsPassword: false,
      };
    }

    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
  }

  return {
    success: false,
    status: 'ERROR',
    verdict: 'ERROR',
    message: 'This is taking longer than expected. Please try again.',
    needsReview: false,
    needsPassword: false,
  };
}

/**
 * One Aadhaar PDF. Its pages already carry both faces, so no second file.
 *
 * ⚠ `password` is usually unnecessary — the server derives it from the
 *   employee's profile. Pass it only after a response with
 *   `needsPassword: true`.
 */
export const verifyAadhaarPdf = async (
  pdfFile: File,
  password?: string,
): Promise<IAadhaarVerifyResponse> => {
  const form = new FormData();
  form.append('front', pdfFile, pdfFile.name);
  if (password) form.append('password', password);
  return submitAndAwait(form);
};

/**
 * Two photographs. **Both are required** — CONTRACTS.md §11.
 *
 * ⛔ The UIDAI signature covers the QR payload only, never the printed face, so
 *    a genuine back paired with a forged front would verify perfectly. That
 *    attack needs the two faces to come from different sources; two photographs
 *    can, the pages of one PDF cannot. Hence one PDF is enough and one photo is
 *    not — the server returns 400 for a lone image.
 */
export const verifyAadhaarPhotos = async (
  frontFile: File,
  backFile?: File | null,
): Promise<IAadhaarVerifyResponse> => {
  const form = new FormData();
  form.append('front', frontFile, frontFile.name);
  if (backFile) form.append('back', backFile, backFile.name);
  return submitAndAwait(form);
};
