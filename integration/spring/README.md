# M-One HRM ↔ AVS integration — Step 10

Java 17 · Spring Boot 3.x · PostgreSQL · callback delivery

Copy `src/main/java/cloud/mone/hrm/aadhaar/` and the Flyway migration into the
HRM repository. Nothing here depends on the Python service being in the same
repo — it talks to AVS over HTTP.

---

## ⛔ Read this before wiring anything

**`AvsCallbackController` is the single most security-critical file in the
integration.**

It is reachable from wherever AVS runs. If it accepted an unsigned body, anyone
who could reach that URL could POST:

```json
{"job_id": "...", "verdict": "VERIFIED", "proof": {"valid": true}}
```

…and the HRM would approve a forged Aadhaar. Every piece of cryptography on the
Python side — the RSA check against UIDAI's key, the pinned trust store, the
hash-chained audit trail — would be bypassed by one unauthenticated POST.

**The chain of trust ends in that file.** Do not add a "temporary" bypass for
local testing.

---

## Wiring

### 1. Configuration

```yaml
avs:
  base-url: https://avs.internal.m-one.cloud
  tenant-id: m-one-prod
  secret: ${AVS_TENANT_SECRET}
  callback-secret: ${AVS_CALLBACK_SECRET}
  connect-timeout: 5s
  read-timeout: 30s
```

```java
@EnableConfigurationProperties(AvsProperties.class)
```

Generate each secret with `openssl rand -hex 32`. `AvsProperties` refuses to
start on a missing, short or placeholder value — deliberately, because a service
running with `changeme` as a signing key looks healthy right up until someone
tries it.

The same two secrets go into the AVS `tenants.json`, as environment variable
*names*:

```json
{"tenants": [{"tenant_id": "m-one-prod",
              "secret_env": "AVS_TENANT_SECRET",
              "callback_secret_env": "AVS_CALLBACK_SECRET"}]}
```

### 2. Migration

`V1__aadhaar_verification.sql` is Flyway-ready and verified against
PostgreSQL's own parser.

### 3. Submitting

```java
var record = aadhaarVerificationService.submit(
        employeeId, frontImageBytes, backImageBytes, requestId);
// returns immediately — the verdict arrives by callback
```

**Both faces are required.** The UIDAI signature covers the QR payload only,
never the printed card, so one image cannot be a complete document. Do not
assume the QR is on the back; placement varies by card format.

### 4. Approving

```java
if (record.isApproved()) { ... }
```

That checks the verdict **and** `signatureValid`. Never approve on the verdict
string alone — requiring both means every approval traces back to an RSA
signature that verified against UIDAI's public key.

---

## The two rules the HRM must not break

**Rule 1 — `VERIFIED` is the only auto-approval.** The database enforces it:

```sql
CONSTRAINT verified_requires_valid_signature
    CHECK (verdict <> 'VERIFIED' OR signature_valid = TRUE)
```

No future code path, migration or manual `UPDATE` can approve something the
cryptography did not.

**Rule 2 — nothing is ever auto-rejected.** Every other verdict goes to a
re-upload prompt or a human. `AvsVerdict.isAutoReject()` exists only to return
`false`, so a reader looking for auto-rejection finds the reason it is absent.

⚠ **The word "fake" must never reach an employee.** Use the `userMessage` the
service supplies. A genuine card photographed badly is indistinguishable from a
forgery to any automated check, which is exactly why no automated check may
call it one.

---

## What is deliberately not stored

**No full Aadhaar number, ever.** The Secure QR contains only the last four
digits, so a full number could only exist by constructing one. The schema
CHECK-constrains `aadhaar_last4` to exactly four digits, so a wrong value fails
the INSERT rather than being stored quietly.

**No images.** AVS never persists them (proven by a test on that side), and this
integration does not send them anywhere else. Where the HRM keeps the originals
is your decision — see the note in `PROJECT_STATE.md` about permanent image
retention being worth reconsidering.

---

## Verified end to end

A Java-built, Java-signed multipart request was sent to a live Python AVS
instance during Step 10:

```
Java built 305998 bytes of multipart + signature
JAVA-BUILT REQUEST -> PYTHON SERVICE : HTTP 202
poll: DONE  verdict=VERIFIED  3260ms
```

The HMAC construction was compared byte-for-byte across six cases — JSON bodies,
empty bodies, binary multipart bodies, non-ASCII secrets, and both halves of the
canonicalisation-collision pair. All six agree.

Two details that silently break integrations, both handled here:

- **Sign the exact bytes on the wire.** `AvsClient` builds the multipart body by
  hand because any library that regenerates it — different boundary, header
  order, line endings — produces bytes that no longer match the signature. The
  symptom is an unexplained 401.
- **Verify the raw body before parsing.** Jackson normalises key order and
  whitespace, so re-serialising a parsed object yields a different signature
  than AVS computed.

---

## Timing

| | |
|---|---|
| Submit returns | immediately (202) |
| Verdict arrives | 3–12 s later, by callback |
| Verified on real cards | ~3.3 s |

Nothing blocks an HTTP worker thread. Holding one for 8 seconds means a handful
of concurrent uploads exhausts the pool and the whole HRM stops responding.
