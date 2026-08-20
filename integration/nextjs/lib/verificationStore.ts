/**
 * Persisting a verified Aadhaar to the HRM database. SERVER ONLY.
 *
 * ★ WHY THIS IS A NARROW, SWAPPABLE MODULE
 *
 *   One exported function, `saveVerification`. The Postgres implementation is
 *   below it and is the only thing that knows about SQL.
 *
 *   If your HRM does not expose its database to the Next.js app — quite likely
 *   for a multi-tenant SaaS — replace the body of `saveVerification` with a
 *   call to your internal API and change nothing else. That seam is deliberate:
 *   I do not know your database topology, and guessing it into the route
 *   handler would have made it expensive to correct.
 *
 * ⛔ ONLY APPROVED VERIFICATIONS ARE STORED.
 *
 *    A real card, signed, signature checked. Everything else shows the employee
 *    a re-upload message and is never written — so failed attempts, and the
 *    identity data inside them, do not accumulate in your database.
 *
 * ⛔ RULE 1 IS CHECKED HERE **AND** IN THE DATABASE.
 *
 *    The guard in `assertApproved` is not redundant with the CHECK constraint
 *    in `migrations/001_aadhaar_verification.sql`. They fail at different times
 *    and protect against different mistakes: the code guard rejects a bad write
 *    with a readable error at the call site, and the constraint catches
 *    anything that reaches the database by another route — a future service, a
 *    migration, a manual UPDATE. Documentation can be forgotten and application
 *    code can be bypassed. The constraint cannot.
 */

import 'server-only';

import type { AvsDecision } from './avsClient';

export interface VerificationRecord {
  readonly jobId: string;
  readonly employeeId: string;
  readonly tenantId: string;
  readonly decision: AvsDecision;
  readonly requestId?: string;
  readonly processingMs?: number;
}

/**
 * ⛔ The pair, restated. `VERIFIED` alone is not approval.
 *
 *    A mislabelling bug upstream could produce the verdict without the
 *    signature; this refuses to record it as an approval, loudly, rather than
 *    letting a forged document acquire a permanent row saying it was genuine.
 */
function assertApproved(decision: AvsDecision): void {
  const approved = decision.verdict === 'VERIFIED' && decision.signature_valid === true;
  if (!approved) {
    throw new Error(
      `refusing to store a non-approved verification: verdict=${decision.verdict} ` +
        `signature_valid=${decision.signature_valid}`,
    );
  }
}

/**
 * Record one approved verification. Safe to call repeatedly for the same job.
 *
 * ⚠ IDEMPOTENT ON `job_id`, and it has to be. The browser polls until the job
 *   settles, so this is reached once per poll after completion — and a user who
 *   refreshes mid-check starts polling again. Without `ON CONFLICT DO NOTHING`
 *   a single verification would produce several rows, and the duplicate
 *   detection in Step 18 joins on this table.
 *
 * @returns true when a row was written, false when one already existed.
 */
export async function saveVerification(record: VerificationRecord): Promise<boolean> {
  assertApproved(record.decision);
  return insertPostgres(record);
}

// --------------------------------------------------------------------------
// PostgreSQL implementation — the only part that knows about SQL.
// --------------------------------------------------------------------------

/**
 * ⚠ `pg` is not bundled with this reference folder. Install it in your app:
 *
 *       npm install pg @types/pg
 *
 * The pool is module-scoped so Next.js reuses one across requests. Creating a
 * pool per request exhausts Postgres connections under any real load, and the
 * failure appears as intermittent timeouts rather than as an obvious mistake.
 */
let pool: import('pg').Pool | undefined;

async function getPool(): Promise<import('pg').Pool> {
  if (!pool) {
    const { Pool } = await import('pg');
    const connectionString = process.env.HRM_DATABASE_URL;
    if (!connectionString) throw new Error('HRM_DATABASE_URL is not set');
    pool = new Pool({ connectionString, max: 5 });
  }
  return pool;
}

async function insertPostgres(record: VerificationRecord): Promise<boolean> {
  const client = await getPool();

  /**
   * ⛔ NOTHING PERSONAL IS WRITTEN HERE, DELIBERATELY.
   *
   *    AVS returns the holder's name, date of birth and full address in
   *    `result`, and the schema has columns for them. This route never receives
   *    those fields — the poll handler forwards only `decision`, so they cannot
   *    be written by accident.
   *
   *    If you later decide the HRM needs the demographics, that is a conscious
   *    change in two places (the poll route must forward them, and this INSERT
   *    must name them) rather than something that happened quietly because the
   *    data was in scope.
   *
   * ⚠ Parameterised, not interpolated. `employeeId` comes from a request
   *   header; string-building this query would be an injection hole.
   */
  const result = await client.query(
    `INSERT INTO aadhaar_verification
       (job_id, employee_id, tenant_id, verdict, signature_valid,
        user_message, processing_ms, request_id, completed_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
     ON CONFLICT (job_id) DO NOTHING`,
    [
      record.jobId,
      record.employeeId,
      record.tenantId,
      record.decision.verdict,
      record.decision.signature_valid,
      record.decision.message,
      record.processingMs ?? null,
      record.requestId ?? null,
    ],
  );

  return (result.rowCount ?? 0) > 0;
}
