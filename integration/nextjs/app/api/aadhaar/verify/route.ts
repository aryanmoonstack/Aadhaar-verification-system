/**
 * HRM upload endpoint — Step 11.
 *
 * ⛔ THIS EXISTS SO THE BROWSER NEVER TALKS TO AVS DIRECTLY.
 *
 *    Calling AVS requires an HMAC signature over the request body. A browser
 *    cannot hold a signing secret — anything shipped to the client is public,
 *    however it is obfuscated. So images come here, and the server signs.
 *
 *    In the M-One deployment this route forwards to the Spring backend from
 *    Step 10, which owns the tenant secret and the verification records. The
 *    Next.js layer is a session-authenticated proxy, nothing more.
 *
 * ⛔ THIS ROUTE MAKES NO DECISION.
 *
 *    It does not inspect the images, does not decode anything, and returns a
 *    job id rather than a verdict. Verification is an RSA signature check
 *    against UIDAI's public key, and it happens in exactly one place.
 */

import { NextRequest, NextResponse } from 'next/server';

/** Refuse absurd uploads before buffering them. Two 12MP JPEGs is ~10MB. */
const MAX_UPLOAD_BYTES = 32 * 1024 * 1024;

export async function POST(request: NextRequest) {
  // Replace with your session helper. An unauthenticated caller must never
  // reach the backend — this route submits work on behalf of a named employee.
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

  // ⛔ Both faces. CONTRACTS.md §11 — the signature covers the QR payload only,
  //    never the printed face, so one image cannot be a complete document.
  if (!(front instanceof File) || !(back instanceof File)) {
    return NextResponse.json(
      { error: 'both the front and back of the card are required' },
      { status: 400 },
    );
  }

  const upstream = new FormData();
  upstream.append('front', front, 'front.jpg');
  upstream.append('back', back, 'back.jpg');
  upstream.append('employeeId', employeeId);

  // Forwarded so one id spans the browser, the HRM and AVS logs.
  const requestId = request.headers.get('x-request-id') ?? crypto.randomUUID();

  const response = await fetch(`${process.env.HRM_API_URL}/api/kyc/aadhaar/submit`, {
    method: 'POST',
    body: upstream,
    headers: {
      'X-Request-ID': requestId,
      // Server-to-server credential. Never sent to the browser.
      Authorization: `Bearer ${process.env.HRM_SERVICE_TOKEN}`,
    },
  });

  if (!response.ok) {
    // ⚠ Do not surface upstream detail to the browser. It is operational
    //    information, and it is not something the employee can act on.
    return NextResponse.json(
      { error: 'We could not start the check just now. Please try again shortly.' },
      { status: 502 },
    );
  }

  const body = await response.json();
  return NextResponse.json({ jobId: body.jobId, requestId });
}
