# Handover to the M-One HRM team

After Steps 10 and 11. **Yes — there is work you can hand over now**, and some
that should wait.

---

## The short answer

| | |
|---|---|
| **Backend dev** | 12 Java files + 1 SQL migration. Ready to integrate. |
| **Frontend dev** | 4 TypeScript files + 27 tests. Ready to integrate. |
| **You** | Deploy AVS, generate two secrets, pin the certificates. |
| **Wait for later steps** | HR review screen (Step 20), duplicate detection (Step 18), profile matching (Step 18). |

Nothing here is a prototype. The Java signing was proven byte-for-byte against
the running Python service, and a Java-built request produced a real `VERIFIED`
in 3.3 seconds.

---

## 1. Backend developer — `integration/spring/`

Copy `src/main/java/cloud/mone/hrm/aadhaar/` into the HRM and the migration into
your Flyway directory.

| File | What it does |
|---|---|
| `AvsSignature` | HMAC signing and verification, both directions |
| `AvsClient` | Signed submission to AVS |
| `AadhaarSubmitController` | `POST /submit`, `GET /status/{jobId}`, `GET /review-queue` |
| **`AvsCallbackController`** | **Receives the verdict. Read the warning below.** |
| `AadhaarVerificationService` | The only class the rest of the HRM should touch |
| `AadhaarVerification` + repository | JPA entity and queries |
| `AvsVerdict`, `AvsResult`, `AvsProperties` | Contract types and config |
| `V1__aadhaar_verification.sql` | PostgreSQL schema |
| `AvsSignatureTest` | 8 tests including the cross-language vector |

### ⛔ Tell them this before they open the files

**`AvsCallbackController` is where the chain of trust ends.** It is reachable
from wherever AVS runs. If it accepted an unsigned body, anyone who could reach
that URL could POST `{"verdict":"VERIFIED"}` and approve a forged Aadhaar —
bypassing the RSA check, the pinned trust store and the audit trail in a single
request.

The HMAC is verified over the **raw body, before parsing**. Do not add a bypass
"just for local testing".

**Rule 1 is enforced by the database, not by convention:**

```sql
CHECK (verdict <> 'VERIFIED' OR signature_valid = TRUE)
CHECK (aadhaar_last4 ~ '^[0-9]{4}$')
```

No future migration or manual `UPDATE` can approve something the cryptography
did not, and storing a full Aadhaar number fails the INSERT rather than
succeeding quietly.

**Approve only via `record.isApproved()`.** It checks the verdict *and*
`signatureValid`. Checking the verdict string alone would mean a mislabelling
bug could approve a forgery.

### What they must write themselves

- Session authentication on `/submit` and `/review-queue`
- Wiring `employeeId` from your existing employee model
- `@EnableConfigurationProperties(AvsProperties.class)`

### Expect one round of small fixes

I had no `javac` or Maven, so the Java is **written and unit-tested by
construction, not compiled**. What I could verify, I did: the HMAC against the
live Python service, the multipart bytes against the real server, the DDL
against PostgreSQL's own parser. The first `mvn test` may still surface an
import or a style nit. Send it to me and I'll fix it.

---

## 2. Frontend developer — `integration/nextjs/`

| File | |
|---|---|
| `lib/qrPrecheck.ts` | Decodes the QR **in the browser before upload** |
| `lib/captureQuality.ts` | Resolution, blur and QR-size rules |
| `components/AadhaarCapture.tsx` | Two-sided camera capture with live guidance |
| `app/api/aadhaar/verify/route.ts` | Session-authenticated proxy to Spring |
| `lib/__tests__/` | 27 tests, `tsc --strict` clean |

### ⛔ Tell them this

**The browser must never call AVS directly.** It cannot hold an HMAC secret —
anything shipped to a client is public. Images go to the HRM, which signs
server-side. A refactor that "simplifies" this puts your tenant key in a
JavaScript bundle.

**The pre-check is not a verdict.** The browser decodes only to answer *"is this
photo good enough to send?"* `PrecheckResult` has no `verified` field and a test
asserts it never gains one.

**Never write the word "fake" in any employee-facing string.** A genuine card
photographed badly is indistinguishable from a forgery to any automated check,
which is exactly why no automated check may call it one. Use the `userMessage`
the service returns — it is deliberately worded.

### Three capture settings that decide whether this works

These are not preferences. Every 2.3 MP image in the real corpus failed to
decode; 12.2 MP images decoded 36% of the time.

- Camera requested at **3840px ideal** — a default stream is often exactly the
  2.3 MP that failed
- **JPEG quality 0.95**, not the 0.8 default — artefacts land precisely on the
  high-contrast edges that define QR modules
- Pre-check every **600ms**, not every frame — continuous decoding stutters the
  preview, making the camera harder to hold steady

### What they must write themselves

- The session helper in `route.ts` (marked `// Replace with your session helper`)
- Styling — the component ships unstyled
- A polling loop against `GET /api/kyc/aadhaar/status/{jobId}`
- `npm install zxing-wasm` only if you support Safari or Firefox

---

## 3. Yours before a pilot

**Deploy AVS** behind TLS. `avs serve --tenants tenants.json --audit audit.jsonl`

**Generate two secrets** — `openssl rand -hex 32` each. One for requests, one
for callbacks. Both go into the environment on each side, never into a file.

**⚠ Pin the certificates.** You have five in `certs/` and no `FINGERPRINTS.txt`,
which means anyone who can write to that directory can add a certificate and
mint approvals:

```powershell
python -m avs.cli certs pin --dir certs
```

**Alert on `avs_decode_rate < 0.85`.** It is the primary metric and it measured
22.7% on real photos before Step 11.

---

## 4. Wait for later steps — do not build these now

| Feature | Step | Why wait |
|---|---|---|
| HR review screen | 20 | The `review-queue` endpoint exists; the UI comes with the reviewer tooling |
| Duplicate detection | 18 | Repository query exists but is unused. Needs the matching rules |
| Name/DOB profile matching | 18 | Needs fuzzy matching — Indian name variants are their own problem |
| Capture-quality model | 14 | The heuristics shipped in Step 11 are the interim version |
| On-device guidance model | 16 | Improves the pre-check; the pre-check already works |

If a developer asks "should I add duplicate checking?" — no. The query is there
so the schema is right, but the *rules* around it are Step 18.

---

## 5. What is honestly still unknown

**The real-world decode rate after Step 11.** It was 22.7% before, and the
browser pre-check should raise it sharply because it stops unusable photos being
sent at all — but that is a prediction, not a measurement. The first week of
`avs_decode_rate` will tell you.

**The camera flow has never run in a browser.** The logic is type-checked and
tested; `getUserMedia` and `BarcodeDetector` need a real device. Test Android
Chrome first — it has the native detector.

**Permanent image storage.** You chose to keep Aadhaar images permanently in the
HRM. I'd still gently push back: after verification the signed QR fields plus
the verdict and reference hash *are* the proof, and they are cryptographically
stronger than a photograph. Keeping the images adds permanent liability without
adding evidentiary value. Storing the verdict record permanently makes complete
sense. Your call, and cheap to change now.

---

## Suggested order

1. Backend: migration + entity + service, no AVS calls yet
2. You: deploy AVS, generate secrets, pin certificates
3. Backend: wire `AvsClient` and the callback, test against the live service
4. Frontend: capture component against the real `/submit`
5. Pilot with 5–10 volunteers, watch `avs_decode_rate`

Steps 1 and 2 are independent, so both developers can start immediately.
