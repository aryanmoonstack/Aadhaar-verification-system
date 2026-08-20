/**
 * Poll one verification job — Step 11, CONTRACTS.md 2.0.0.
 *
 * ⛔ Server-side, for the same reason as the submit route: the poll is signed
 *    too, and a browser cannot hold the signing key.
 *
 * ★ WHAT THIS RETURNS AND WHY IT IS SHAPED THIS WAY
 *
 *   The browser gets the `decision` block and nothing else. AVS also returns a
 *   full `result` — identity fields, address, per-side outcomes, the AI trace —
 *   and none of that belongs in a browser. It is personal data the upload
 *   screen has no use for, and forwarding it would put an employee's address
 *   into a response any browser extension can read.
 */

import { NextRequest, NextResponse } from 'next/server';

import { AvsJobNotFound, AvsUnavailable, needsPassword, poll } from '@/lib/avsClient';
import { saveVerification } from '@/lib/verificationStore';

/** ⛔ Node, not Edge. The Edge runtime has no `node:crypto` for HMAC. */
export const runtime = 'nodejs';

export async function GET(
  request: NextRequest,
  context: { params: Promise<{ jobId: string }> },
) {
  const employeeId = request.headers.get('x-employee-id');
  if (!employeeId) {
    return NextResponse.json({ error: 'not authenticated' }, { status: 401 });
  }

  const { jobId } = await context.params;

  // ⚠ Bind the job to the employee who submitted it before shipping this.
  //   Job ids are UUIDs and therefore unguessable, but unguessable is not the
  //   same as authorised — anyone who learns an id could otherwise read
  //   someone else's verification outcome. Store the id against the employee
  //   at submit time and check it here.

  try {
    const status = await poll(jobId);

    // Still working. The client keeps polling.
    if (!status.decision) {
      return NextResponse.json({ jobId, status: 'PENDING', decision: null });
    }

    // ⛔ Record an APPROVED verification in the HRM. Only approved ones —
    //    a failure shows the employee a re-upload message and is not stored,
    //    keeping failed attempts and their identity data out of the database.
    //
    // ⚠ Written here rather than from an AVS callback. The callback would be
    //   more robust — it lands even if the employee closes the tab — but it is
    //   the most security-critical endpoint in the integration, and adding it
    //   for a one-to-two-second window is a poor trade today. A missed write is
    //   self-healing: the employee re-uploads and it verifies again.
    if (status.decision.status === 'APPROVED') {
      try {
        await saveVerification({
          jobId,
          employeeId,
          tenantId: process.env.AVS_TENANT_ID ?? 'm-one-prod',
          decision: status.decision,
        });
      } catch (storeError) {
        // ⛔ A STORAGE FAILURE MUST NOT BECOME A VERIFICATION FAILURE.
        //
        //    The cryptography already succeeded — this employee's card is
        //    genuine and they are entitled to be told so. Turning a database
        //    outage into "your Aadhaar could not be verified" would accuse
        //    someone of a problem with their document because OUR database was
        //    down, which is precisely the confusion CONTRACTS.md §1 exists to
        //    prevent.
        //
        //    So: log loudly for operators, and tell the employee the truth.
        console.error('aadhaar.store.failed', { jobId, employeeId, error: storeError });
      }
    }

    // ⛔ Only the decision crosses to the browser. Never `result` — it carries
    //    the holder's name, date of birth and full address.
    //
    // ⚠ `needsPassword` is the one exception, and it is a BOOLEAN derived from
    //   an error code, not the code itself. It exists because a locked PDF and
    //   a blurry photo both arrive as RETRY/UNREADABLE, and the generic message
    //   sends someone with a perfect file off to retake a photograph.
    const askForPassword = needsPassword(status);

    return NextResponse.json({
      jobId,
      status: status.status,
      decision: status.decision,
      needsPassword: askForPassword,
      // ⛔ Phrased as a FIRST REQUEST, deliberately. When the derived password
      //    misses, the employee never typed anything — telling them "that
      //    password was wrong" would be accusing them of a mistake the system
      //    made on their behalf.
      passwordPrompt: askForPassword
        ? 'This PDF is password-protected. Please enter its password — for an ' +
          'e-Aadhaar it is the first 4 letters of your name in CAPITALS ' +
          'followed by your year of birth, for example RAME1990.'
        : null,
    });
  } catch (error) {
    if (error instanceof AvsJobNotFound) {
      return NextResponse.json({ error: 'unknown job' }, { status: 404 });
    }
    if (error instanceof AvsUnavailable) {
      return NextResponse.json(
        { error: 'We could not reach the checking service. Please try again shortly.' },
        { status: 502 },
      );
    }
    throw error;
  }
}
