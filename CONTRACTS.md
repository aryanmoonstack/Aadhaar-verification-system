# CONTRACTS — Frozen Interfaces

**Frozen:** Step 0 · 13 August 2026
**Version:** 1.9.0

> ## ⛔ READ BEFORE CHANGING ANYTHING IN THIS FILE
>
> Everything here is **frozen**. Every step from 1 to 25 is built against these
> definitions. A silent change breaks steps built weeks earlier.
>
> **To change a contract:**
> 1. Bump the version at the top of this file
> 2. List every consuming module (check `PROJECT_STATE.md` → Module Registry)
> 3. Update each consumer in the same commit
> 4. Record the change in the Changelog at the bottom
>
> Adding a *new* contract is fine. Changing or removing an existing one is not.

---

## 1. Verdicts — exactly 9, no more

The complete set of outcomes. **No step may invent a tenth.**

| Verdict | Meaning | Auto-approve | Human review | Retry allowed |
|---|---|:---:|:---:|:---:|
| `VERIFIED` | Valid UIDAI signature + identity matched | ✅ **only one** | — | — |
| `TAMPERED` | QR decoded, **signature invalid** | ❌ | ✅ | ✅ |
| `UNREADABLE` | No QR could be decoded | ❌ | — | ✅ |
| `LEGACY_FORMAT` | Pre-2018 unsigned QR — cannot be verified | ❌ | — | ✅ |
| `WRONG_DOCUMENT` | Not an Aadhaar card | ❌ | — | ✅ |
| `PROFILE_MISMATCH` | Signature valid, name/DOB differs from profile | ❌ | ✅ | ✅ |
| `TEXT_MISMATCH` | Signature valid, printed text ≠ signed fields | ❌ | ✅ | ✅ |
| `DUPLICATE` | This Aadhaar is already bound to another employee | ❌ | ✅ | ❌ |
| `ERROR` | Processing failure | ❌ | ✅ | ✅ |

### Two absolute rules

**Rule 1 — `VERIFIED` is the only auto-approval, and it requires
`signature_valid == True`.** No other condition, combination of conditions, or model
output may produce it.

**Rule 2 — Nothing is ever auto-rejected.** Every non-`VERIFIED` outcome routes to a
re-upload prompt or a human reviewer. The system never tells an employee they
committed fraud.

### Language rule

The word **"fake"** must never appear in employee-facing text. Use
**"could not be verified."** A genuine card photographed badly is not a forgery.

---

## 2. Check Names — canonical

Every entry in `checks[]` uses one of these exact names.

| Check | Produced by | Step | Can it decide the verdict? |
|---|---|:---:|---|
| `file_validation` | `ingest/` | 3 | Blocks only |
| `document_type` | `ai/classify/` | 13 | ❌ advisory |
| `capture_quality` | `ai/quality/` | 14 | ❌ advisory |
| `qr_localised` | `ai/localize/` | 15 | ❌ advisory |
| `qr_decoded` | `qr/` | 5 | Blocks only |
| `payload_parsed` | `parser/` | 1 | Blocks only |
| **`signature_verify`** | **`crypto/`** | **1** | ✅ **THE VERDICT** |
| `side_agreement` | `rules/` | 6 | ❌ review only |
| `ocr_cross_check` | `ocr/` | 17 | ❌ review only |
| `profile_name_match` | `matching/` | 18 | ❌ review only |
| `profile_dob_match` | `matching/` | 18 | ❌ review only |
| `duplicate_check` | `matching/` | 18 | ❌ review only |

**`signature_verify` is the only check that can produce `VERIFIED`.**

### Check results
`PASS` · `FAIL` · `WARN` · `SKIP` (feature disabled or not applicable)

---

## 3. Error Codes

**Ingest** — `FILE_TOO_LARGE` `FILE_TOO_SMALL` `UNSUPPORTED_MIME_TYPE` `CORRUPT_IMAGE`
`DIMENSIONS_INVALID` `DECOMPRESSION_BOMB` `MALWARE_DETECTED`

**Decode** — `QR_NOT_FOUND` `QR_DECODE_FAILED`

**Parse** — `PAYLOAD_MALFORMED` `PAYLOAD_UNSUPPORTED_VERSION` `PAYLOAD_LEGACY_UNSIGNED`
`PAYLOAD_TRUNCATED`

**Crypto** — `SIGNATURE_INVALID` `TRUSTSTORE_EMPTY` `CERTIFICATE_EXPIRED`
`CERTIFICATE_LOAD_FAILED`

**Service** — `STORAGE_FETCH_FAILED` `CALLBACK_FAILED` `TIMEOUT` `RATE_LIMITED`
`INVALID_REQUEST`

**AI** — `MODEL_LOAD_FAILED` `MODEL_INFERENCE_FAILED` (both non-fatal — degrade gracefully)

**General** — `INTERNAL_ERROR`

Every error carries: `code` · `message` · `retryable: bool` · `request_id`

---

## 4. Aadhaar Field Names — canonical

Extracted from the Secure QR. These names are used everywhere: internal models, API
responses, database columns.

**Identity** — `name` `dob` `gender` `aadhaar_last4` `reference_id`

**Address** — `care_of` `house` `street` `landmark` `location` `vtc` `sub_district`
`district` `state` `pincode` `post_office`

**Optional** — `mobile_hash` `email_hash` `photo` (JPEG2000 bytes)

### Canonical field ORDER — UIDAI spec, not our invention

Transcribed verbatim from UIDAI "SECURE QR CODE SPECIFICATION" (March 2019) §3.1:

```
_presence, reference_id, name, dob, gender,
care_of, district, landmark, house, location,
pincode, post_office, state, street, sub_district, vtc
```

⚠ The address order is **not** the logical postal order. `district` precedes
`house`; `pincode` precedes `state`. Guessing it puts the district in the house
column on every card — and the signature still verifies, because it covers raw
bytes and knows nothing about our labels. Cryptography cannot catch a naming
error. Only the specification can.

Some cards carry a leading `"V2"` marker; most follow the spec and start at
`_presence`. Both occur in the wild, so the parser tries both layouts and keeps
whichever yields a valid `reference_id`.

> ### ⛔ The full 12-digit Aadhaar number
> It is **not present in the Secure QR** — only the last 4 digits are. There is
> therefore no field for it, and no code path may ever construct, store, log, or
> transmit one. This is enforced structurally, not by policy.

---

## 5. Signature Verification — the security invariant

```
signed_data = payload_bytes[:-256]      # everything EXCEPT the last 256 bytes
signature   = payload_bytes[-256:]      # the final 256 bytes

verify(signature, signed_data, uidai_public_key, RSA-PKCS1v15, SHA-256)
```

**This byte range is the single most dangerous thing in the codebase.** Getting it
wrong produces false verdicts while every test that doesn't specifically check it
still passes. It must never be modified without re-running the full genuine +
tampered corpus.

Every certificate in the trust store is tried in turn; **any** match means valid.

---

## 6. Module Interfaces

Defined as Python `Protocol` classes in `avs.contracts.protocols`. Each module
implements its Protocol. This is how a step built in week 8 plugs correctly into
something built in week 1.

| Protocol | Implemented by | Step |
|---|---|:---:|
| `Ingestor` | `ingest/` | 3 |
| `VariantGenerator` | `imaging/` | 4 |
| `QrDecoder` | `qr/` | 5 |
| `PayloadParser` | `parser/` | 1 |
| `SignatureVerifier` | `crypto/` | 1 |
| `CertificateStore` | `truststore/` | 2 |
| `VerdictEngine` | `rules/` | 6 |
| `PrivacyFilter` | `privacy/` | 6 |
| `DocumentClassifier` | `ai/classify/` | 13 |
| `QualityAssessor` | `ai/quality/` | 14 |
| `QrLocalizer` | `ai/localize/` | 15 |
| `ImageRestorer` | `ai/restore/` | 19 |
| `TextCrossChecker` | `ocr/` | 17 |
| `NameMatcher` | `ai/namematch/` | 18 |
| `IdentityBinder` | `matching/` | 18 |

Every one of them is loaded through a single component:

| Component | Provides | Step |
|---|---|:---:|
| `ai/modelmgr/registry.py` | `ModelSpec`, `ModelRegistry` — SHA-256-pinned model files | 12 |
| `ai/modelmgr/runtime.py` | `ModelRunner`, `InferenceOutcome` — bounded, degrading inference | 12 |
| `ai/classify/` | `build_classifier()`, `HeuristicClassifier`, `OnnxDocumentClassifier`, `extract_features()` | 13 |

**Optional-by-design:** every AI Protocol may be absent at runtime. The pipeline
accepts `None` for each and continues deterministically. AI is an accelerator,
never a dependency.

**What Step 12 turns from intention into mechanism.** "Optional" was previously a
convention each AI module had to honour separately, and five modules honouring a
convention separately is five chances to get it wrong. `ModelRunner` now owns
every failure path — absent model, absent `onnxruntime`, failed digest, throwing
graph, hanging graph, empty output — and each ends in `None`, meaning *carry on
deterministically*. `ModelRunner.with_fallback()` is the shape every AI module
uses, so no module can forget its fallback.

**Models are pinned like certificates.** An ONNX graph is executable content
interpreted by `onnxruntime`, so `models.json` records a SHA-256 for each file
and the registry refuses any file that differs — the same reasoning as
`certs/FINGERPRINTS.txt`. A model is capped by `max_inference_ms` (default 500ms,
against a 12s document budget); a model that exceeds it is abandoned, not waited
for.

---

## 7. The AI Boundary — architectural law

```
   AI ──────────► INPUT SIDE
                  classify · quality · localize · restore
                  purpose: make bad images decodable

   ✕  ──────────  THE VERDICT
                  crypto.verify() — RSA-2048 / SHA-256
                  no AI, no heuristics, no thresholds, no scores

   AI ──────────► HUMAN-ASSIST SIDE
                  ocr · namematch · assist · support · anomaly
                  purpose: make review fast and fair
```

**Why this is safe rather than merely cautious:** the signature check sits
*downstream* of everything AI touches. If a model degrades, mispredicts, or
hallucinates, the worst outcome is a re-upload prompt — **never a false approval**.
Forging an approval would require UIDAI's private key, which no amount of image
enhancement can produce.

**Enforcement, in both directions.** `rules/` accepts only `CheckOutcome`
objects and has no access to model confidences. `tests/unit/test_ai_boundary.py`
then asserts, by AST inspection of every source file:

1. No decision module (`rules`, `crypto`, `parser`, `truststore`) imports `avs.ai`.
2. **No `avs.ai` module imports `avs.crypto`, `avs.rules`, `avs.truststore` or
   `avs.parser`.** Added in Step 12. This is the more likely accident of the two:
   the natural shape of *"I just need a bit more context here"* is an import, and
   a model that can see a signature is one refactor away from influencing it.
3. `InferenceOutcome` — what every model returns — has no field an approval could
   be read from (`verdict`, `verified`, `is_genuine`, `authentic`,
   `signature_valid`, `approved`, `valid`). A type-level guard catching what an
   import check cannot.
4. Every AI parameter on `DocumentVerifier.__init__` defaults to `None`.

**Step 13 — the first AI output to reach the verdict object.** Everything before
it was upstream of the decision (preprocessing) or outside the service entirely
(the browser pre-check). The classifier is the first component whose output
travels alongside a verdict, so the boundary is now enforced at runtime as well
as by module layout:

| | |
|---|---|
| **When it runs** | Only after `rules.decide()` has returned, and only when the verdict is `UNREADABLE` |
| **What it may write** | `user_message` and `ai_trace` |
| **What it may not write** | `verdict`, `proof`, `checks`, `error` — it never receives them |
| **A VERIFIED document** | Is never classified at all. No output exists that would have to be ignored |

`tests/unit/test_classify_never_changes_verdict.py` runs the whole pipeline
against a classifier that returns *every* `DocType` at confidence 1.0 and
asserts the verdict, proof, error and check list are identical to the run with
no classifier at all. A component that lies about everything, with total
certainty, still cannot move the outcome.

---

## 8. REST API — `/v1/`

### ⛔ Authentication — required on every `/v1` route (Step 8)

Each request carries four headers:

```
X-AVS-Tenant     tenant id
X-AVS-Timestamp  unix seconds
X-AVS-Nonce      unique per request
X-AVS-Signature  hex HMAC-SHA256 over  timestamp + "." + nonce + "." + body
```

The key is the tenant's shared secret. The **dot separators are part of the
contract** — without them `("12","3")` and `("1","23")` hash identically and an
attacker can shift bytes between the timestamp and the nonce.

| Rule | |
|---|---|
| Clock skew | ±300 s. Outside that, rejected. |
| Replay | A nonce is accepted once. Re-sending a captured request fails. |
| Failure | Always `401` with `{"code":"INVALID_REQUEST","message":"authentication failed"}` |

⚠ **The 401 body is identical for every cause.** Distinguishing "unknown
tenant" from "bad signature" from "replay" hands an attacker an oracle for
enumerating tenants. Our logs carry the real reason; the caller gets one word.

`/health`, `/ready` and `/metrics` are **unauthenticated** — a load balancer
cannot sign, and they expose nothing about any document.

The signature covers the **raw body bytes**, including a multipart payload. Sign
exactly what goes on the wire.

**Implemented in Step 7.** Fields marked ⏳ are planned for the step named and are
not yet accepted.

> **Correction in 1.4.0.** The 1.3.0 draft of this section showed a single
> `source_url`. That predates §11, which requires **both card faces** — the
> signature covers the QR payload only, never the printed face, so one image can
> never be a complete document. The request carries `front_url` and `back_url`.

### `POST /v1/verify` → `202 Accepted`  (pre-signed URLs)
```jsonc
{
  "front_url": "https://...presigned",   // required
  "back_url":  "https://...presigned",   // required
  "job_id": "uuid",                      // optional; generated when absent
  "strictness": "STANDARD",              // optional: LENIENT | STANDARD | STRICT
  "callback_url": "https://hrm.internal/api/kyc/callback",
  "tenant_id": "uuid",                   // ⏳ Step 9
  "employee_id": "uuid",                 // ⏳ Step 9
  "expected": { "name": "…", "dob": "YYYY-MM-DD" },   // ⏳ Step 12 (text match)
  "client_hints": { "capture_method": "CAMERA" }      // ⏳ Step 13
}
```

⛔ **`front_url` and `back_url` are an SSRF surface.** Both are checked
**synchronously, before a job is created**:

| Outcome | Status | `retryable` | Meaning |
|---|---|---|---|
| Loopback / private / link-local / reserved / unspecified address | `400` | `false` | Permanently refused |
| Non-http(s) scheme | `400` / `422` | `false` | Permanently refused |
| DNS resolution failed | `503` | `true` | Transient — retry |

A refused URL creates **no job** and consumes **no queue slot**. The check runs
on the **resolved address**, not the hostname, and redirects are never followed.

### `POST /v1/verify/upload` → `202 Accepted`  (multipart)
Form fields: `front` (file, required) · `back` (file, required) · `job_id` ·
`callback_url` · `strictness`. Missing either face → `422`.

### `POST /v1/verify/sync` → `200 OK`
Same multipart body, blocks for the full 7–12 s and returns the result directly.
Admin and debugging only — not for the HRM.

### `GET /v1/verify/{job_id}` → `200 OK`
```jsonc
{ "job_id": "…", "status": "QUEUED|RUNNING|DONE|FAILED",
  "result": { … }, "error": null, "queued_ms": 3, "duration_ms": 6748 }
```
Unknown or expired job → `404`. Results are retained for 15 minutes.

### Response to a submission
```jsonc
{ "job_id": "…", "status": "QUEUED", "estimated_seconds": 12,
  "already_queued": false }
```

**`job_id` is idempotent.** Re-submitting a known id returns the existing job
with `already_queued: true` and does **not** run the verification again. A client
retrying after a timeout must not be charged twice, and one document must not
produce two conflicting audit records.

**Overload** → `503` with `Retry-After: 10` and code `RATE_LIMITED`.

### Error body shape
Every non-2xx carries:
```jsonc
{ "detail": { "code": "<ErrorCode>", "message": "…", "retryable": true|false } }
```

### `GET /ready` → `200` / `503`
⚠ **`/ready` is not `/health`.** `/health` reports that the process is alive.
`/ready` reports that it can *verify*, which requires a usable certificate and at
least one QR decoder. With an empty trust store every genuine document returns
`ERROR`, so `/ready` returns `503` and the load balancer must stop sending work.

```jsonc
{ "ready": true, "certificates": 1, "certificate_status": "OK",
  "days_to_certificate_expiry": 364, "decoders": ["zxing-cpp", "opencv"],
  "queue_depth": 0, "reason": null }
```

### `GET /metrics` → Prometheus

| Metric | Alert |
|---|---|
| **`avs_decode_rate`** | **below 0.85** — employees are being asked to re-upload |
| `avs_certificate_days_to_expiry` | below 90 |
| `avs_certificate_pinning` | equals 0 — anyone who can write to `certs/` can mint approvals |
| `avs_ready` | equals 0 |
| `avs_auth_rejected_total` | sustained rise — misconfigured client, or probing |

Also: `avs_up` · `avs_queue_depth` · `avs_uptime_seconds` ·
`avs_documents_total` · `avs_documents_decoded_total` ·
`avs_processing_ms_mean` · `avs_verdict_total{verdict}` ·
`avs_decoder_success_total{decoder}` · `avs_strategy_success_total{strategy}`

⚠ **`avs_decode_rate` is the primary metric.** It existed only in an offline
script until Step 9, which is how a real-world rate of 22.7% went unnoticed
while 540 tests passed.

### Request correlation

Every response carries `X-Request-ID`. Send your own to continue a trace begun
in the HRM; one is generated otherwise. It appears on every log line for that
document.

### Callback → HRM
```jsonc
{
  "job_id": "uuid",
  "verdict": "VERIFIED",
  "method": "SECURE_QR_RSA2048",
  "proof": { "signature_valid": true, "certificate_serial": "…",
             "qr_version": "V2", "signed_byte_length": 1482 },
  "extracted": { "name": "…", "dob": "…", "gender": "…",
                 "aadhaar_last4": "1234", "reference_hash": "hmac-sha256:…",
                 "address": { … } },
  "checks": [ { "name": "signature_verify", "result": "PASS" } ],
  "ai_trace": { "models_used": [], "restoration_invoked": false, "total_ai_ms": 0 },
  "user_message": "Aadhaar verified successfully.",
  "purge_after": "2026-08-14T10:22:41Z",
  "processing_ms": 1840
}
```

**Callback security:** HMAC-SHA256 over the raw body, with timestamp and nonce.
Headers: `X-AVS-Signature` `X-AVS-Timestamp` `X-AVS-Nonce`.

**Planned routes:** `GET /v1/certificates` ⏳ Step 9 · `GET /v1/models` ⏳ Step 12

---

## 9. Accepted Input

**Accepted:** JPEG · PNG · HEIC/HEIF · WebP
**Rejected:** PDF · archives · executables · Office documents · SVG · HTML

**Limits:** 50 KB – 20 MB · min 640×480 · max 12000×12000

> **PDF is deliberately out of scope** (decision recorded 13 Aug 2026). Input is
> phone-camera and scanner images only. Do not reintroduce PDF handling in any step
> without a contract version bump.

---

## 10. Logging & Privacy

- **Never log:** raw image bytes · QR payload strings · full names with DOB together ·
  anything resembling a 12-digit number
- **Always log:** `request_id` · `job_id` · `tenant_id` · verdict · check names + results
- Redaction is applied by `avs.logging.redaction` at the formatter level — it cannot be
  bypassed by a careless log call
- Any 12-digit sequence is replaced with `[AADHAAR-REDACTED]` before output

---

## 11. Two-Sided Capture

**The employee uploads BOTH sides of the Aadhaar card. Both are required.**

### Why — the signature does not cover the printed card

The UIDAI signature protects the **QR payload only**. It says nothing about the
ink printed on the card face. That leaves one real attack open:

> Take a genuine Aadhaar back with a valid Secure QR. Pair it with a **forged
> front** showing a different name and photograph. The signature verifies
> perfectly — because the QR genuinely is genuine. Only the printed face is fake.

Collecting both sides and diffing the printed text against the signed QR fields
is what closes it. This is what `ocr/` (Step 17) exists for.

The front adds no *data* — the QR already carries name, DOB, gender, full
address, photo and last-4. It adds **evidence**, plus a usable photograph for HR
review and any future face matching.

### The QR may be on either side

Placement varies by card format. PVC cards carry the Secure QR on the back; the
classic printed letter often carries it on the front; some e-Aadhaar printouts
have both.

**Never assume "QR = back".** The pipeline runs on both images and accepts the
Secure QR from whichever side yields one.

### Rules

| Situation | Behaviour |
|---|---|
| Either side yields a valid Secure QR | The QR is the source of truth. Verdict follows §1 Rule 1. |
| Both sides yield a Secure QR | Payloads must match. A mismatch is `TEXT_MISMATCH` → human review. |
| Neither side yields a Secure QR | `UNREADABLE` (or `WRONG_DOCUMENT` if `foreign_qr_found`). |
| **QR verifies, other side unreadable** | **`VERIFIED`.** The signature is cryptographic proof; that verdict does not depend on the second photo being sharp. The image is retained for review and the cross-check runs on whatever is legible. |
| Printed text contradicts the signed QR fields | `TEXT_MISMATCH` → human review. Never auto-rejected. |

The unreadable-second-side behaviour is **per-tenant policy**, keyed off the
existing `Strictness` setting. `STANDARD` (default) approves as above; `STRICT`
routes to human review instead. No tenant may configure auto-rejection — §1
Rule 2 is absolute.

### Verdict is per DOCUMENT, not per image

Steps 0–5 are per-image and unchanged. Step 6 adds a document-level layer above
them: run the existing pipeline on each side, then produce one
`VerificationResult` for the pair.

---

## Changelog

| Version | Date | Change |
|---|---|---|
| 1.0.0 | 2026-08-13 | Initial freeze (Step 0) |
| 1.9.0 | 2026-08-17 | **§6 gains `ai/classify/`; §7 gains the runtime rules for AI output that travels with a verdict (Step 13).** Additive — `DocumentClassifier` was already declared in §6 and is unchanged. The new material is §7's table of what the classifier may and may not write, and the fact that a VERIFIED document is never classified at all. Consumers reviewed: `pipeline/` (gains an optional `classifier=` parameter, default `None`); `api/`, Spring and Next.js unchanged — refinement only alters `user_message`, which they already display verbatim. |
| 1.8.0 | 2026-08-17 | **§6 gains the model registry and inference runtime; §7's enforcement becomes bidirectional (Step 12).** Additive — no existing interface changes. §6 documents `ai/modelmgr/`, which makes "optional-by-design" a mechanism rather than a convention: one component owns every model failure path, and models are SHA-256-pinned exactly as UIDAI certificates are. §7 now states the reverse boundary — the AI layer may not import the decision layer — plus the type-level guard on `InferenceOutcome`. Consumers reviewed: `ai/` (empty until Step 13, so nothing to migrate); `pipeline/` unchanged. |
| 1.7.0 | 2026-08-14 | **§8 gains the observability surface (Step 9).** Additive. `avs_decode_rate` and the per-stage counters make the project's primary metric visible in production for the first time — it previously existed only in `scripts/corpus_report.py`, which is why a 22.7% real-world rate went unnoticed. Adds `X-Request-ID` correlation, `avs_certificate_pinning`, and the `/ready` fields `pinning_enabled`, `tenants`, `auth_required`, `audit_enabled`. Consumers reviewed: `api/` (this step), Spring `AvsClient` (Step 10 — should forward `X-Request-ID`). |
| 1.6.0 | 2026-08-14 | **§8 gains mandatory HMAC authentication on every `/v1` route (Step 8).** Additive — no existing field or verdict changes. Step 7 shipped with none, so anything that could reach the port could submit a document and receive a verdict. Same construction as the Step 7 callback dispatcher, so the HRM implements one scheme in both directions. Health probes stay open. Consumers reviewed: `api/` (this step), Spring `AvsClient` (Step 10, not yet built — must sign requests), Next.js UI (Step 11, calls the HRM, never AVS directly). |
| 1.5.0 | 2026-08-14 | **§4 gains the canonical field ORDER, transcribed from UIDAI's specification.** Additive — no existing name changes. Motivation: the order had been inferred rather than sourced, and `FIELD_MAPS` carried a phantom leading `_version` field that UIDAI's format does not contain. The test fixture emitted the same phantom field, so fixture and parser agreed while both disagreed with every real card. Recorded here so the order can never again be re-derived from intuition. Consumers reviewed: `parser/` (corrected), `ocr/` (Step 17), `matching/` (Step 18). |
| 1.4.0 | 2026-08-14 | **§8 rewritten to match the API built in Step 7.** One correction and several additions. *Correction:* the 1.3.0 draft showed a single `source_url`; §11 (1.3.0) requires both card faces, so the request carries `front_url` + `back_url`. The old shape could never have expressed a complete document and was never implemented. *Additions:* `POST /v1/verify/upload` (multipart), the `202` submission body with `already_queued`, `job_id` idempotency, the standard error body `{code, message, retryable}`, the SSRF disposition table (400 permanent / 503 transient, refused **before** a job is created), `/ready` semantics vs `/health`, and the `/metrics` series. `GET /v1/certificates` and `GET /v1/models` moved from "other routes" to planned. Consumers reviewed: `api/` (Step 7, this step), Spring `AvsClient` (Step 10, not yet built), Next.js UI (Step 11, not yet built). |
| 1.3.0 | 2026-08-13 | **Two-sided capture becomes a requirement** (new §11). The employee uploads both the front and back of the card. Rationale: the UIDAI signature covers the QR payload only, not the printed card face, leaving a genuine-back-plus-forged-front attack open. The QR may be on either side and must be found wherever it is. Verdict becomes per-*document* rather than per-image. Steps 0-5 are unaffected — they remain per-image. Consumers reviewed: `rules/` (Step 6, scope extended), `ocr/` (Step 17), `api/` (Step 7), Spring + Next.js (Steps 10-11). |
| 1.2.0 | 2026-08-13 | Two changes, both backwards compatible. (a) `QrDecoder.decode` accepts `Iterable[ImageVariant]` instead of `list` — matches the 1.1.0 widening of `VariantGenerator.generate`, so the cascade can consume the lazy stream. (b) `DecodeResult` gains `foreign_qr_found: bool = False` — additive with a default. A photo may contain a QR that is not an Aadhaar Secure QR (a URL sticker, an app UI); distinguishing "no QR at all" from "a QR, but the wrong one" produces materially better employee guidance. Consumers reviewed: `qr/` (Step 5, this step), `rules/` (Step 6, not yet built). |
| 1.1.0 | 2026-08-13 | `VariantGenerator.generate` returns `Iterable[ImageVariant]` instead of `list`. **Widening, not breaking** — a list still satisfies the annotation. Motivation: a 12 MP photo expanded into ~40 encoded variants is several hundred MB, and the Step 5 cascade stops at the first success, so materialising them all is waste. Implementations may now be lazy. Consumers reviewed: `qr/` (Step 5, not yet built) — no existing code affected. |
