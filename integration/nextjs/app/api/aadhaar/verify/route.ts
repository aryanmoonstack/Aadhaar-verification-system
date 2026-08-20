/**
 * Aadhaar upload endpoint — Step 11, revised for CONTRACTS.md 2.0.0.
 *
 * ⛔ THIS EXISTS SO THE BROWSER NEVER TALKS TO AVS DIRECTLY.
 *
 *    Calling AVS requires an HMAC signature over the request body, and a
 *    browser cannot hold a signing secret — anything shipped to the client is
 *    public, however it is obfuscated.
 *
 *    ⚠ "The frontend calls AVS" is still true, and this is how. A Next.js route
 *      handler is server-side code: it runs in Node, not in the browser. The
 *      frontend team owns this file and the secret lives in its environment.
 *      No separate backend service is involved.
 *
 * ⛔ THIS ROUTE MAKES NO DECISION.
 *
 *    It does not inspect the files, does not decode anything, and returns a job
 *    id rather than a verdict. Verification is an RSA signature check against
 *    UIDAI's public key and it happens in exactly one place.
 */

import { NextRequest, NextResponse } from 'next/server';

import { derivePdfPassword } from '@/lib/aadhaarPdfPassword';
import { AvsUnavailable, submit } from '@/lib/avsClient';

/** ⛔ Node, not Edge. The Edge runtime has no `node:crypto` for HMAC. */
export const runtime = 'nodejs';

/** Refuse absurd uploads before buffering them. Two 12MP JPEGs is ~10MB. */
const MAX_UPLOAD_BYTES = 32 * 1024 * 1024;

const PDF_TYPE = 'application/pdf';

/**
 * ⚠ Content, not filename. Browsers report `type` from the extension, which is
 *   a claim the user controls — so this decides only whether to ACCEPT a single
 *   file. AVS re-detects from magic bytes and has the final say, meaning a lie
 *   here cannot smuggle anything through; it can at most produce a clearer
 *   error one hop later.
 */
async function looksLikePdf(file: File): Promise<boolean> {
  if (file.type === PDF_TYPE) return true;
  const head = Buffer.from(await file.slice(0, 5).arrayBuffer());
  return head.toString('latin1') === '%PDF-';
}

export async function POST(request: NextRequest) {
  // Replace with your session helper. An unauthenticated caller must never
  // reach AVS — this route submits work on behalf of a named employee.
  const employeeId = request.headers.get('x-employee-id');
  if (!employeeId) {
    return NextResponse.json({ error: 'not authenticated' }, { status: 401 });
  }

  const declaredLength = Number(request.headers.get('content-length') ?? 0);
  if (declaredLength > MAX_UPLOAD_BYTES) {
    return NextResponse.json({ error: 'upload too large' }, { status: 413 });
  }

  const form = await request.formData();
  const front = form.get('front');
  const back = form.get('back');
  const password = form.get('password');

  if (!(front instanceof File)) {
    return NextResponse.json({ error: 'a file is required' }, { status: 400 });
  }

  const hasBack = back instanceof File && back.size > 0;

  // ⛔ CONTRACTS.md §11. Two IMAGES are required; one PDF is sufficient alone.
  //
  //    The rule exists to stop a genuine card back being paired with a forged
  //    front. That attack needs the two faces to come from DIFFERENT sources —
  //    two photographs can, the pages of one PDF cannot.
  if (!hasBack && !(await looksLikePdf(front))) {
    return NextResponse.json(
      {
        error:
          'Please upload both the front and the back of your Aadhaar card. ' +
          'If you have the Aadhaar PDF, you can upload that on its own instead.',
      },
      { status: 400 },
    );
  }

  // Forwarded so one id spans the browser, this route and the AVS logs.
  const requestId = request.headers.get('x-request-id') ?? crypto.randomUUID();

  // ── The PDF password ────────────────────────────────────────────────────
  //
  // ⚠ Order matters. A password the employee TYPED always wins over a derived
  //   one: they are looking at the document and we are guessing from a profile
  //   that may not match it. Overriding their input with our guess would make
  //   the manual field appear to do nothing.
  //
  // ⛔ Name and DOB are read SERVER-SIDE, from the session profile — never from
  //    the request body. A browser-supplied name would let anyone compute a
  //    password for a document belonging to someone else.
  //
  //    Replace these headers with your real session helper. They are a
  //    stand-in, exactly like `x-employee-id` above.
  const typed = typeof password === 'string' && password ? password : null;
  const derived =
    typed ??
    derivePdfPassword({
      name: request.headers.get('x-employee-name'),
      birthYear: request.headers.get('x-employee-birth-year'),
    });

  try {
    const { jobId } = await submit({
      front,
      back: hasBack ? (back as File) : null,
      // ⛔ In memory for the life of this request, then gone. Never logged,
      //    never stored, and the PDF is never decrypted to disk — AVS takes the
      //    password directly.
      password: derived,
      requestId,
    });
    return NextResponse.json({ jobId, requestId }, { status: 202 });
  } catch (error) {
    if (error instanceof AvsUnavailable) {
      // ⚠ Never surface the upstream status. A 401 from AVS means OUR secret is
      //   wrong — an operational fault the employee cannot act on and should
      //   not be shown.
      return NextResponse.json(
        { error: 'We could not start the check just now. Please try again shortly.' },
        { status: 502 },
      );
    }
    throw error;
  }
}
