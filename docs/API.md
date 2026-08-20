# AVS API

**Contract 2.0.0.** Read from the running service, not from memory.

Base URL: wherever AVS is deployed. **HTTPS in production** — Aadhaar images
cross this link.

---

## Endpoints

| Method | Path | Auth | |
|---|---|---|---|
| `POST` | `/v1/verify/upload` | HMAC | **Submit files.** → 202 |
| `GET` | `/v1/verify/{job_id}` | HMAC | Poll for the answer → 200 |
| `POST` | `/v1/verify/sync` | HMAC | Same, blocking. Avoid — holds a thread |
| `POST` | `/v1/verify` | HMAC | JSON with pre-signed URLs instead of files |
| `GET` | `/health` | public | Liveness |
| `GET` | `/ready` | public | Certificates, pinning, auth, tenants |
| `GET` | `/metrics` | public | Prometheus. **Alert on `avs_decode_rate`** |
| `GET` | `/docs` | public | Interactive OpenAPI |

Two endpoints do the work: **`POST /v1/verify/upload`**, then poll
**`GET /v1/verify/{job_id}`**.

---

## Authentication

Four headers on every `/v1/` call:

```
X-AVS-Tenant      m-one-prod
X-AVS-Timestamp   1755500000        unix SECONDS
X-AVS-Nonce       <random hex, unique per request>
X-AVS-Signature   <hex>
```

Signature = HMAC-SHA256 over **`timestamp + "." + nonce + "." + rawBody`**, hex.

A `GET` has no body, so its canonical string ends at the final dot:
`1755500000.abc123.` — the body is an empty byte string, not a skipped part.

### Three things that will cost you an afternoon

**1. The signature covers the RAW body bytes.**

Both reference clients build their multipart body **by hand** for this reason.
Any library that regenerates the body — a different boundary, a different header
order — transmits bytes you did not sign. Measured against a live service:

```
FormData / auto-generated body   ->  HTTP 401
hand-built byte buffer           ->  HTTP 202
```

The 401 says "authentication failed" while your secret is perfectly correct.
See `integration/nextjs/lib/avsSignature.ts` — verified byte-for-byte against
the Python service across six shared vectors, pinned in
`lib/__tests__/avsSignature.test.ts`.

**2. The dot separators are load-bearing.**

Without them `("12","3",body)` and `("1","23",body)` hash identically, letting
an attacker shift bytes between the timestamp and the nonce while keeping a
valid signature. Not formatting.

**3. Nonces are single-use.** Replaying one returns 401. Fresh per request.

---

## POST /v1/verify/upload

`multipart/form-data`. **Only `front` is required.**

| Field | | |
|---|---|---|
| `front` | **required** | An image, or a whole PDF |
| `back` | conditional | The other face. Required for images, omitted for a PDF |
| `password` | optional | For an encrypted PDF |
| `job_id` | optional | Supply your own; resubmitting the same id returns the existing job |
| `callback_url` | optional | AVS POSTs the result here when it settles |
| `strictness` | optional | `LENIENT` / `STANDARD` / `STRICT` |

**202 Accepted** → `{ "job_id": "...", "status": "PENDING" }`

### Two images, or one PDF

| Submitted | |
|---|---|
| Two images | ✅ |
| One PDF | ✅ — its pages carry both faces |
| One image | ❌ **400**, with a message naming the PDF alternative |
| PDF + image | ✅ |

⛔ **Why a lone image is refused but a lone PDF is not.** The UIDAI signature
covers the QR payload only, never the printed face — so a genuine back paired
with a **forged front** would verify perfectly. The signature really is genuine;
it just says nothing about the face beside it.

That attack needs the two faces to come from **different sources**. Two
photographs can. The pages of one PDF cannot — they arrived as one file.

⚠ The QR may be on **either** side, and on **any page**. Never assume "QR =
back" or "QR = page 1"; AVS searches all of them.

### PDF notes

- Pages are rendered at 300 DPI and searched in order (first 4 pages).
- ★ **A PDF should decode far better than a photo.** It holds the QR as vector
  data, so a render has no blur, glare or JPEG ringing — the defects that held
  the measured photo corpus to roughly 30%.
- e-Aadhaar PDFs from UIDAI are password-protected. Pass `password`; it is held
  in memory only and never logged, stored or returned.

---

## GET /v1/verify/{job_id}

```json
{
  "job_id": "93435715-204c-48ca-90bf-3eaebb524ef2",
  "status": "DONE",
  "decision": {
    "status_code": 200,
    "status": "APPROVED",
    "message": "Your Aadhaar has been verified.",
    "needs_review": false,
    "verdict": "VERIFIED",
    "signature_valid": true
  },
  "result": { "...": "full detail — identity, address, checks, per-side outcomes" }
}
```

⚠ **Two different `status` fields, deliberately.**

- Top-level `status` — **job lifecycle**: `PENDING` or `DONE`. Poll on this.
- `decision.status` — **the outcome**: `APPROVED` / `RETRY` / `REVIEW`.

`decision` is `null` until the job settles. Poll every ~1s; a verified card
typically settles in 1–3 seconds.

### The decision block

| Field | |
|---|---|
| `status_code` | 200 approved · 422 retry · 202 review |
| `status` | `APPROVED` \| `RETRY` \| `REVIEW` |
| `message` | Show verbatim |
| `needs_review` | Whether HR should look. **Independent of `status`** |
| `verdict` | The underlying verdict, unabridged |
| `signature_valid` | Whether an RSA signature verified |

⛔ **`status_code` is carried in the BODY.** It is not the HTTP status. Polling
a job that failed verification is a *successful* poll — HTTP 200, with a body
saying `RETRY`. A client that keys error handling off the HTTP status will fire
on perfectly good responses.

⛔ **There is no `REJECTED` value.** Nothing is ever auto-rejected. A genuine
card photographed badly is indistinguishable from a forgery to any automated
check — which is exactly why no automated check may call it one. On the measured
corpus roughly 70% of unguided photos failed to decode; a REJECTED status would
have accused most of those employees of fraud.

⛔ **Never rewrite `message`.** It is worded so it never accuses anyone. The word
"fake" must not appear in employee-facing text.

⚠ **`needs_review` is separate from `status` on purpose.** `TAMPERED` tells the
employee to re-upload *and* alerts a reviewer. One field cannot carry both
audiences, so they travel side by side.

---

## The nine verdicts

| Verdict | `status` | `needs_review` | |
|---|---|:---:|---|
| `VERIFIED` | APPROVED | — | Signature valid against a pinned UIDAI certificate |
| `UNREADABLE` | RETRY | — | No QR could be read |
| `LEGACY_FORMAT` | RETRY | — | Pre-2018 card, no Secure QR |
| `WRONG_DOCUMENT` | RETRY | — | A QR decoded, but not an Aadhaar one |
| `TAMPERED` | RETRY | ✅ | QR decoded, signature did not verify |
| `ERROR` | RETRY | ✅ | **Our** fault — certificates missing, service problem |
| `PROFILE_MISMATCH` | REVIEW | ✅ | Details differ from the employee profile |
| `TEXT_MISMATCH` | REVIEW | ✅ | The two faces disagree |
| `DUPLICATE` | REVIEW | ✅ | Already registered to another employee |

`RETRY` means a better or different file fixes it. `REVIEW` means it cannot —
asking the employee to try again would send them in a circle.

⛔ **Approve only on the pair:**

```
verdict == "VERIFIED" && signature_valid === true
```

That is what `saveVerification()` asserts before writing a row, and what the
`verified_requires_valid_signature` CHECK constraint in
`migrations/001_aadhaar_verification.sql` enforces independently. AVS applies
the same rule when building `decision`: a
`VERIFIED` verdict arriving without a valid proof is **downgraded to REVIEW**,
not approved — so an upstream bug surfaces to a human instead of quietly
approving a forgery.

---

## Errors

| Status | |
|---|---|
| 202 | Accepted, queued |
| 400 | Bad request — lone image, unsupported type, blocked URL |
| 401 | Auth failed. The log says which: missing headers, bad signature, replayed nonce |
| 404 | Unknown `job_id` |
| 413 | File too large |
| 422 | Malformed multipart |
| 503 | Not ready — usually no certificates loaded |

Ingest error codes appear per side in `result.sides[].error`, including
`PDF_PASSWORD_REQUIRED` and `PDF_PASSWORD_INCORRECT`. Those two are split
deliberately: "supply a password" and "correct the one you supplied" need
opposite things from the employee, and the renderer reports both identically.

---

## Callback (optional)

Pass `callback_url` on submit; AVS POSTs the result when it settles, so the
employee is not left polling.

```
POST <your callback_url>
Content-Type: application/json
X-AVS-Signature / X-AVS-Timestamp / X-AVS-Nonce
```

⛔⛔ **The most security-critical endpoint in the integration.** It is reachable
from wherever AVS runs. If it accepted an unsigned body, anyone able to reach
that URL could POST `{"verdict":"VERIFIED"}` and approve a forged Aadhaar —
bypassing the RSA check, the pinned trust store and the audit trail in one
request.

Verify the HMAC over the **raw body, before parsing**. Raw, because Jackson
normalises key order and whitespace. Before parsing, because running a parser on
attacker-controlled input precedes establishing who sent it.

⚠ **No callback client currently exists.** The Next.js integration polls
instead, so `callback_url` is unused today. If you add one, verify the HMAC over
the raw body before parsing, and do not add a bypass "just for local testing".

---

## GET /ready

```json
{
  "ready": true,
  "certificates": 5,
  "certificate_status": "OK",
  "days_to_certificate_expiry": 900,
  "pinning_enabled": true,
  "auth_required": true,
  "tenants": 1,
  "decoders": ["zxing-cpp", "opencv"],
  "queue_depth": 0
}
```

`certificates: 0` → every card returns `ERROR`, genuine ones included.
`pinning_enabled: false` → anyone who can write to `certs/` can mint approvals.

---

## Timing

Measured, synthetic cards, 5 s budget:

| | |
|---|---|
| Two images | **~0.4 s** |
| 1-page PDF | **~1.7 s** |
| 3-page PDF, QR on the last page | ~6.4 s |
| Nothing readable | the full budget |

Deploy with `--budget 5`. A card that decodes succeeds on the first
preprocessing variant, so the budget only ever costs **failures** time.

⚠ PDF rendering (~0.3 s/page/file) sits *outside* the budget, so a multi-page
PDF can exceed it. A real e-Aadhaar carries the QR on page 1, which is the 1–2 s
case.

---

## Before going live

```powershell
python -m avs.cli certs pin --dir certs
python scripts\preflight.py --url https://<the AVS URL>
```

`preflight` sends no images and reads no cards, and refuses a clean bill of
health while certificates, pinning, auth or tenants are wrong.
