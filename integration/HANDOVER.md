# Handover to the M-One HRM team

**Contract 2.0.0.** Rewritten 20 Aug 2026, when the architecture changed: the
frontend now calls AVS directly and the Spring backend was dropped.

---

## The short answer

| | |
|---|---|
| **Frontend dev** | Owns the whole integration. 8 TypeScript files + 80 tests. |
| **Backend dev** | One SQL migration to apply. Nothing else. |
| **You** | Deploy AVS, generate two secrets, pin the certificates. |
| **Later steps** | HR review screen (Step 20), duplicate detection (Step 18), profile matching (Step 18). |

⚠ **What changed, and why it matters if you saw the previous version.** There
were 12 Java files here. They were deleted, not lost: the Next.js route handler
now signs and calls AVS itself, so the Java HTTP client, HMAC signing and
controllers had no caller. The signing proof survives — `lib/avsSignature.ts`
carries its own six vectors verified against the Python service.

The one file that did **not** become dead is the database schema, which moved to
`migrations/001_aadhaar_verification.sql`. It encodes two constraints nothing
else enforces.

---

## 1. Frontend developer — `integration/nextjs/`

This is now the entire integration. Copy into the HRM app.

| File | |
|---|---|
| `lib/avsSignature.ts` | HMAC signing + hand-built multipart. **The risky part** |
| `lib/avsClient.ts` | Transport. `server-only` |
| `lib/aadhaarPdfPassword.ts` | Derives the e-Aadhaar password from the profile |
| `lib/verificationStore.ts` | Writes approved verifications to the HRM database |
| `app/api/aadhaar/verify/route.ts` | Submit. Signs server-side |
| `app/api/aadhaar/verify/[jobId]/route.ts` | Poll. Records the result |
| `components/AadhaarUpload.tsx` | File picker, pre-check, PDF + password |
| `lib/qrPrecheck.ts`, `captureQuality.ts`, `exif.ts` | Browser pre-check |

```bash
npm install pg @types/pg server-only
cp .env.example .env.local     # then fill it in
```

### ⛔ Tell them this before they open the files

**1. The secret is server-side, and one prefix decides that.**

`AVS_SECRET` is read only inside route handlers, which run in Node. Naming it
`NEXT_PUBLIC_AVS_SECRET` would compile the signing key into the JavaScript every
visitor downloads. `import 'server-only'` makes a mistaken client import fail the
**build** rather than leak quietly.

**2. Never replace the hand-built multipart with `FormData`.**

The signature covers the raw body bytes. Handing a `FormData` to `fetch` lets
undici generate the body with its own boundary at send time — you sign one byte
sequence and transmit another. Measured against a live service with auth on:

```
FormData (regenerated body)  ->  HTTP 401
hand-built Buffer            ->  HTTP 202
```

The 401 reads as a credential problem while the credentials are perfect.

**3. Approve only on the pair.**

```ts
decision.verdict === 'VERIFIED' && decision.signature_valid === true
```

`saveVerification()` asserts this before writing, and the database constraint
enforces it independently.

**4. Never rewrite `decision.message`.** It is worded so it never accuses anyone.
The word "fake" must not appear in employee-facing text — a genuine card
photographed badly is not a forgery.

**5. The pre-check must never block upload.** A photo the browser cannot read may
still decode on the server, which runs 23 preprocessing variants the browser
does not, and Safari has no detector at all.

### The PDF password is derived, not asked for

An e-Aadhaar from UIDAI is encrypted, and most employees do not know it has a
password. The submit route computes it from their profile — first 4 characters
of the name in capitals plus the birth year — so the password box normally never
appears. It is shown only when that derivation misses.

⛔ **Name and DOB must come from the SESSION, never the request body.** A
browser-supplied name would let anyone compute a password for someone else's
document. The reference reads `x-employee-name` and `x-employee-birth-year` as
stand-ins; replace them with your session lookup.

⚠ **A miss is ordinary, not exceptional** — it happens whenever the HRM name
differs from the Aadhaar name (`Raj Sharma` vs `Rajkumar Sharma`, surname first,
initials). When it happens the employee is *asked*, and the wording is a first
request. Never "wrong password": they typed nothing, the guess was ours.

⛔ **The PDF is never decrypted to disk.** The password is passed to AVS in
memory. Unlocking and re-saving would leave a readable Aadhaar in a temp
directory — exactly what UIDAI encrypted it to prevent.

### Three things left for them, marked in the code

- **Bind `jobId` to the employee** in the poll route. Job ids are UUIDs and
  unguessable, but unguessable is not authorised — anyone who learned an id
  could otherwise read someone else's outcome.
- **Replace the `x-employee-id` header** with your real session helper.
- **Replace `x-employee-name` / `x-employee-birth-year`** with the same session
  lookup, for the password derivation above.

---

## 2. Backend developer — one migration

```
migrations/001_aadhaar_verification.sql
```

Apply it with Flyway, Liquibase or by hand. Plain PostgreSQL, no dependencies.

**Rule 1 is enforced by the database, not by convention:**

```sql
CHECK (verdict <> 'VERIFIED' OR signature_valid = TRUE)
CHECK (aadhaar_last4 IS NULL OR aadhaar_last4 ~ '^[0-9]{4}$')
```

No future migration or manual `UPDATE` can approve something the cryptography
did not, and storing a full Aadhaar number fails the INSERT rather than
succeeding quietly.

⚠ **Only approved verifications are written.** Failures show the employee a
re-upload message and are not stored, so failed attempts and their identity data
never accumulate. The review columns are unused today — `PROFILE_MISMATCH`,
`TEXT_MISMATCH` and `DUPLICATE` are not reachable until Steps 17 and 18. They
exist now so that adding them later is not a migration against live identity
data.

⚠ **If the HRM database is not reachable from the Next.js app** — plausible for a
multi-tenant SaaS — replace the body of `saveVerification()` in
`lib/verificationStore.ts` with a call to your internal API. That function is the
only place that knows how records are stored; nothing else changes.

---

## 3. You — deployment

```powershell
python -m avs.cli certs pin --dir certs
python scripts\preflight.py --url https://<the AVS URL>
```

Two secrets, not three — see `docs/SECRETS.md`. The callback secret is not
needed; the integration polls.

Deploy with `--budget 5`.

---

## What to watch

`avs_decode_rate` in `/metrics`. Alert on `< 0.85`, and on
`avs_certificate_days_to_expiry < 90`.

**30%** was the measured floor on photographs shot deliberately badly with no
guidance. PDFs should be far higher — a rendered e-Aadhaar has no blur, glare or
JPEG ringing. That is a prediction, not a measurement, until real e-Aadhaar PDFs
have been through `scripts/local_e2e.py`.

---

## Known state at handover

| | |
|---|---|
| Steps 0–14 + PDF support | ✅ complete |
| Python tests | 801 |
| TypeScript tests | 80 |
| Real cards over real HTTP | ✅ VERIFIED, signature valid, audit chain intact |
| PDF end to end, auth on | ✅ 202 → APPROVED, Node client → Python service |
| Contract version | 2.0.0, consistent across code and document |
| **Real e-Aadhaar PDF** | ✅ **VERIFIED, 2.3 s** — real UIDAI certificate, real signature |
| Browser pre-check on a device | ❓ `BarcodeDetector` has never executed on real hardware |

⚠ The real-PDF result comes from a corpus of three. One verified; one was a
different person's password; one was a genuinely pre-2018 e-Aadhaar reported
correctly as `LEGACY_FORMAT`. Enough to prove the path works end to end, not
enough to quote a decode rate. Watch `avs_decode_rate` in the pilot.

★ Those three documents also found a bug that 800 tests could not — see D157.
A real e-Aadhaar carries more than one QR, and the page search stopped at the
first code it could read instead of the first *signed* one. Every synthetic
fixture had exactly one QR, so nothing in the suite could have caught it.
