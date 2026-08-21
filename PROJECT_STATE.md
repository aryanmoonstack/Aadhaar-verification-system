# PROJECT STATE

> **Read this at the START of every step. Update it at the END of every step.**
> This file is the project's memory. It is how Step 18, built weeks from now,
> still knows what Step 3 decided.

**Last updated:** 14 August 2026 · end of Step 11 · 🏁 MILESTONE C COMPLETE
**Contract version:** 1.7.0

---

## Current Position

| | |
|---|---|
| **Completed** | Steps 0–14 — 14 of 26. Step 14 is the first component whose thresholds were DERIVED from real decode outcomes rather than chosen, and it found three production bugs on the way. |
| **Next** | Step 15 — QR Localiser |
| **Milestone** | D — AI Vision Layer (Steps 12–16) |
| **Blocked on** | Nothing. Two parallel items for Dheeraj: (a) obtain UIDAI certificates into `certs/` — until then `/ready` returns 503 and every document returns `ERROR`, which is correct; (b) run `scripts/validate_corpus.py` against real cards to confirm `FIELD_MAPS` ordering. Neither blocks Step 8. |

---

## Progress

```
MILESTONE A — Deterministic Core
  [x] Step 0   Foundation & Contract Freeze
  [x] Step 1   Cryptographic Core
  [x] Step 2   Certificate Trust Store
  [x] Step 3   Ingest & Validation
  [x] Step 4   Image Preprocessing
  [x] Step 5   QR Decoder Cascade
  [x] Step 6   Verdict Engine & Privacy      🏁 WORKING VERIFIER

MILESTONE B — Deployable Service
  [x] Step 7   REST API & Async Worker
  [x] Step 8   Auth, Tenancy & Statelessness
  [x] Step 9   Observability & Audit         🏁 DEPLOYABLE SERVICE

MILESTONE C — HRM Integration
  [~] Step 10  Spring Backend Integration    ⚠ SUPERSEDED 20 Aug — see D152
  [x] Step 11  Next.js Upload Flow           🏁 SHIPPABLE FEATURE
  [x] Step 11b PDF support + decision shape  (CONTRACTS 2.0.0)

MILESTONE D — AI Vision Layer
  [x] Step 12  ML Foundation
  [x] Step 13  Document Type Classifier
  [x] Step 14  Capture Quality Model
  [ ] Step 15  QR Localiser                  ← NEXT
  [ ] Step 16  On-Device Browser AI          🏁 decode rate ≥95%

MILESTONE E — Decision Intelligence
  [ ] Step 17  OCR Cross-Check
  [ ] Step 18  AI Name Matching

MILESTONE F — Advanced AI
  [ ] Step 19  Image Restoration
  [ ] Step 20  HR Reviewer Copilot
  [ ] Step 21  Multilingual Assistant

MILESTONE G — Production
  [ ] Step 22  Hardening
  [ ] Step 23  Testing & UAT
  [ ] Step 24  Production Launch             🏁 live
  [ ] Step 25  Anomaly Detection (ongoing)
```

**12 of 26 steps complete.**

---

## Module Registry

Every module, what it provides, and who consumes it. **Update this table whenever a
module is implemented or its interface changes.**

| Module | Step | Status | Provides | Consumed by |
|---|:---:|---|---|---|
| `contracts/` | 0 | ✅ **DONE** | enums, models, Protocols | **everything** |
| `config/` | 0 | ✅ **DONE** | `Settings`, `get_settings()` | all modules |
| `logging/` | 0 | ✅ **DONE** | `configure_logging()`, `redact()` | all modules |
| `cli.py` | 0 | ✅ **DONE** | `avs` entry point | developers |
| `parser/` | 1 | ✅ **DONE** | `SecureQrParser.parse(str) -> QrPayload`, `ParseError` | `crypto/`, `ocr/` |
| `crypto/` | 1 | ✅ **DONE** | `SecureQrVerifier.verify(payload) -> SignatureProof` | `rules/` |
| `truststore/` | 1–2 | ✅ **DONE** | `UidaiCertificate`, `FileCertificateStore`, `TrustStoreHealth`, `ExpiryStatus`, `load_certificate_file()` | `crypto/`, `health/` |
| `ingest/` | 3 | ✅ **DONE** | `ImageIngestor.ingest(bytes) -> ValidatedImage`, `detect()`, `FileKind`, `IngestError`, scanners | `imaging/` |
| `imaging/` | 4 | ✅ **DONE** | `PreprocessingVariantGenerator.generate() -> Iterator[ImageVariant]`, `STRATEGIES`, `Problem`, `select_strategies()`, `ops` | `qr/`, `ai/quality/` |
| `qr/` | 5 | ✅ **DONE** | `QrDecoderCascade.decode(variants) -> DecodeResult`, `classify_payload()`, `PayloadKind`, 4 backends, `decoder_availability()` | `rules/` (Step 6) |
| `rules/` | 6 | ✅ **DONE** | `DeterministicVerdictEngine.decide()`, `MESSAGES`, `message_for()` | `pipeline` |
| `privacy/` | 6 | ✅ **DONE** | `DataMinimisingFilter.apply()`, `reference_hash()` | `pipeline` |
| `pipeline.py` | 6 | ✅ **DONE** | `DocumentVerifier.verify(sides) -> VerificationResult`, `SideInput` | `api/` (Step 7), CLI |
| `api/` | 7 | ✅ **DONE** | `create_app()`, `AppState`, `POST /v1/verify` · `/v1/verify/upload` · `/v1/verify/sync` · `GET /v1/verify/{id}`, `/health` `/ready` `/metrics`, `CallbackDispatcher` | Spring `AvsClient` (Step 10) |
| `worker/` | 7 | ✅ **DONE** | `JobQueue` (Protocol), `InProcessJobQueue`, `Job`, `JobStatus`, `QueueFull` | `api/` |
| `health/` | 7 | ✅ **folded into `api/`** | `/health` `/ready` `/metrics` — a separate module would have needed the same app state | ops |
| `storage/` | 7 | 🟡 **PARTIAL** | `SafeUrlFetcher.fetch(url)`, `is_safe_url() -> UrlCheck`, `FetchError` — SSRF guard done; S3 credentials, retries and object-store writes land in Step 8 | `api/` |
| `security/` | 8 | ✅ **DONE** | `verify_request_signature()`, `sign_request()`, `NonceCache`, `TenantConfig`, `TenantRegistry` (Protocol), `FileTenantRegistry`, `InMemoryTenantRegistry` | `api/` |
| `audit/` | 9 | ✅ **DONE** | `AuditEntry`, `AuditSink` (Protocol), `FileAuditTrail`, `NullAuditSink`, `verify_chain()` | `api/`, CLI |
| `observability/` | 9 | ✅ **folded into `api/`** | `avs_decode_rate` + per-stage counters, `RequestContextMiddleware` correlation ids | ops |
| `ai/modelmgr/` | 12 | ✅ **DONE** | `ModelSpec`, `ModelRegistry`, `load_registry()`, `RegistryError`, `ModelRunner`, `InferenceSession`, `InferenceOutcome`, `onnxruntime_available()` | all `ai/` modules (13–19) |
| `ai/classify/` | 13 | ✅ **DONE** | `build_classifier()`, `HeuristicClassifier`, `OnnxDocumentClassifier`, `DocumentFeatures`, `extract_features()`, `CLASS_ORDER` | `pipeline` (optional), CLI |
| `ai/quality/` | 14 | ✅ **DONE** | `measure_quality()`, `QualityMetrics`, `QualityAssessor.assess()/assess_detailed()`, measured thresholds | `imaging/`, `pipeline` |
| `ingest/pdf.py` | 3.5 | ✅ **DONE** | `render_pdf()`, `RenderedPage`, `PDFIUM_AVAILABLE` — PDF pages to images at the ingest boundary | `ingest/validator.py` only |
| `ai/localize/` | 15 | ⬜ stub | `localize() -> QrRegion` | `qr/` |
| `ocr/` | 17 | ⬜ stub | `cross_check() -> TextSimilarity` | `rules/` |
| `matching/` | 18 | ⬜ stub | `bind() -> MatchOutcome` | `rules/` |
| `ai/namematch/` | 18 | ⬜ stub | `match() -> NameSimilarity` | `matching/` |
| `ai/restore/` | 19 | ⬜ stub | `restore(image)` | `qr/` retry path |
| `ai/assist/` | 20 | ⬜ stub | `summarise(result)` | HR review queue |
| `ai/support/` | 21 | ⬜ stub | `guidance(verdict, locale)` | `api/` |
| `ai/anomaly/` | 25 | ⬜ stub | `evaluate(window)` | ops alerts |

---

## Frozen Decisions

Decisions that later steps must respect. Each records where it was made.

| # | Decision | Step | Rationale |
|---|---|:---:|---|
| D1 | **Verdict enum locked at exactly 9 values** | 0 | Adding a tenth is a contract change; enforced by `test_exactly_nine_verdicts` |
| D2 | **`VERIFIED` is the only auto-approval, and requires `signature_valid == True`** | 0 | CONTRACTS.md §1 Rule 1 |
| D3 | **Nothing is ever auto-rejected** | 0 | CONTRACTS.md §1 Rule 2 — a machine must not accuse an employee of fraud |
| D4 | **`signed_bytes = payload[:-256]`, `signature = payload[-256:]`** | 0 | The security invariant. Changing it requires re-running the full corpus |
| D5 | **No AI module may be imported by `rules/`, `crypto/`, `parser/`, `truststore/`** | 0 | Enforced by `test_ai_boundary.py`, which parses the AST |
| D6 | **No field for the full 12-digit Aadhaar number exists anywhere** | 0 | It isn't in the QR; enforced by `test_no_field_for_full_aadhaar_number` |
| D7 | **PDF input is out of scope** — images only (JPEG/PNG/HEIC/WebP) | 0 | User decision 13 Aug 2026. Do not reintroduce without a contract bump |
| D8 | **Redaction lives in the structlog processor chain, not at call sites** | 0 | A careless log call must still be safe |
| D9 | **All AI Protocols are optional at runtime** | 0 | Model load failure degrades the pipeline; it never fails it |
| D10 | **`str, Enum` not `StrEnum`** for contract enums | 0 | Stable JSON/pydantic behaviour; `UP042` ignored deliberately in ruff config |
| D11 | **Python 3.12**, separate repository from M-One | 0 | User decision |
| D12 | **Base install excludes ML and imaging deps** — optional groups per step | 0 | A broken ML dependency must never block the crypto core |
| D13 | **Field order lives in `FIELD_MAPS`, a declarative table** | 1 | Correcting an ordering after real-card validation is a one-line data change, not a code change |
| D14 | **Parser never verifies; verifier never parses** | 1 | A parsing bug can then never be mistaken for a valid signature |
| D15 | **Invalid signature returns `SignatureProof(valid=False)`, never raises** | 1 | A tampered document is a normal expected outcome, not an exceptional one |
| D16 | **Truncation that makes the signature block overlap text fields is rejected at parse time** | 1 | Yields an accurate `UNREADABLE` rather than `TAMPERED` — a damaged image is not a forgery |
| D17 | **Pre-2018 unsigned QR → `PAYLOAD_LEGACY_UNSIGNED`, never `SIGNATURE_INVALID`** | 1 | A genuine old card must not be reported as a forgery |
| D18 | **`timezone.utc` over `datetime.UTC`** (`UP017` ignored) | 1 | Universally correct; avoids version coupling in security-critical modules |
| D19 | **Test fixtures are synthetic, signed with a throwaway keypair** | 1 | Enables deterministic byte-level tamper testing and keeps all PII out of CI forever |
| D20 | **Certificates loaded from disk at startup, never fetched at runtime** | 2 | Preserves the zero-outbound-internet property |
| D21 | **Store holds MANY certificates; verifier tries every one** | 2 | A single-certificate store silently breaks the day UIDAI rotates |
| D22 | **Certificates sorted newest-expiry-first** | 2 | Current cards match on the first attempt; a rotated-out cert cannot shadow the current one |
| D23 | **Fingerprint pinning via `certs/FINGERPRINTS.txt`** | 2 | Without it, write access to `certs/` is enough to mint approvals |
| D24 | **One unreadable file is a `LoadIssue`, not an exception** | 2 | A single corrupt file must not take down a store that still holds working certificates |
| D25 | **`TrustStoreError` raised only when unsafe to start** — missing dir, or pinning required but absent | 2 | Fail closed on conditions where continuing is worse than not starting |
| D26 | **`days_to_earliest_expiry` ignores already-expired certificates** | 2 | An archived expired cert must not pin the alert permanently negative |
| D27 | **File extension is never used for type detection** — magic bytes only | 3 | An extension is a claim by the uploader; magic bytes are evidence |
| D28 | **Check order: upper size → magic → allow-list → lower size → scan → header → bombs → decode** | 3 | Cheapest and safest first; a 4 KB disguised executable must be named as such, not called "too small" |
| D29 | **ALL EXIF is stripped; orientation applied first** | 3 | Phone photos embed GPS. An Aadhaar photo taken at home would otherwise carry the employee's home coordinates |
| D30 | **Metadata stripped via `Image.new` + `paste`, not by excluding blocks** | 3 | A fresh canvas carries no `info` dict — metadata is left behind by construction, not by remembering each block |
| D31 | **HEIF normalised to JPEG** | 3 | One predictable codec downstream instead of three |
| D32 | **`sha256` is of the ORIGINAL upload bytes, not the normalised output** | 3 | Stable audit identity; a normalised hash would drift with Pillow versions |
| D33 | **ClamAV fails CLOSED when unreachable** (`fail_open` opt-in) | 3 | A scanner that silently stops scanning is worse than none — operators believe they are protected |
| D34 | **Two-message errors: `message` for logs, `user_message` for employees** | 3 | "magic bytes indicate PDF" belongs in a log; the employee needs instructions |
| D35 | **Variant generation is LAZY** — contract 1.1.0 widened the return to `Iterable` | 4 | ~23 encoded variants of a 12 MP photo is hundreds of MB; the Step 5 cascade uses the first success |
| D36 | **Strategies are DATA, not code** — a table of (name, ops, tier, addresses) | 4 | Makes Step 14 a selection change, not a rewrite; the whole policy is readable in one screen |
| D37 | **Ordering is tier, then DECLARATION order — never alphabetical** | 4 | `original` must be variant 1. Alphabetical put `gray` first and added work to every successful upload |
| D38 | **Variants encode as PNG, never JPEG** | 4 | JPEG block ringing lands exactly on QR module edges and can make a decodable code undecodable |
| D39 | **Rotation sweep OFF by default** | 4 | QR finder patterns are rotation-invariant and EXIF orientation is applied in Step 3 — it multiplies work for ~no gain |
| D40 | **`find_document_quad` returns None rather than guessing**, and rejects quads >95% of frame | 4 | A wrong quad corrupts the input; "the document is the whole picture" is not a detection |
| D41 | **`suppress_glare` requires a contiguous blob** (morphological opening first) | 4 | A white card legitimately has many bright pixels; inpainting scattered ones is pure damage |
| D42 | **A failing strategy is skipped, not fatal** | 4 | One broken recipe must not deny the decoder the other twenty-two |
| D43 | **`working_max_edge` is deliberately high (4000px)** | 4 | Downscaling a dense Secure QR below ~3 px/module destroys it irrecoverably; spend the CPU instead |
| D44 | **Loop order is variant-major, decoder-minor** | 5 | Four decoders on one image cost ms; another 12 MP variant costs ~100x that. Decoder-major would force the stream to materialise |
| D45 | **Cascade stops at the FIRST success** | 5 | This is what makes Step 4's tier ordering pay off — measured: 20/21 successes decode on variant 1 |
| D46 | **Not every QR is accepted** — payloads are classified first | 5 | A URL sticker or app UI code would otherwise short-circuit the cascade and reach the parser |
| D47 | **Legacy XML QR is ACCEPTED and passed to the parser** | 5 | Yields `LEGACY_FORMAT` ("download a fresh e-Aadhaar") instead of the misleading `UNREADABLE` |
| D48 | **Every decoder backend is optional** | 5 | pyzbar needs system libzbar; WeChat needs contrib model files. Only OpenCV is guaranteed |
| D49 | **Empty decoder list fails loudly, never silently** | 5 | A silent zero decode rate is far worse than a loud one |
| D50 | **Cascade supports a wall-clock time budget** | 5 | Measured: failures cost ~4.3 s vs ~250 ms for successes. One bad image must not hold a worker |
| D51 | **BOTH sides of the card are uploaded and processed** | 5.5 | The signature covers the QR payload only, not the printed face — a genuine back paired with a forged front would otherwise verify perfectly |
| D52 | **The QR may be on EITHER side — never assume "QR = back"** | 5.5 | Placement varies: PVC cards put it on the back, printed letters often on the front, some e-Aadhaar on both |
| D53 | **Verdict is per DOCUMENT (the pair), not per image** | 5.5 | Steps 0-5 stay per-image and unchanged; Step 6 adds the document-level layer above them |
| D54 | **QR verifies + other side unreadable → `VERIFIED`** | 5.5 | The signature is cryptographic proof; it does not depend on the second photo being sharp. Punishing the employee for a blurry extra photo serves nothing the security model needs |
| D55 | **That behaviour is per-tenant via `Strictness`** — `STRICT` routes to review instead | 5.5 | Uses the policy mechanism already in the contract. No tenant may configure auto-rejection — Rule 2 is absolute |
| D56 | **Both payloads must match when both sides carry a QR** | 5.5 | Two different Secure QRs on one document means the sides came from different cards → `TEXT_MISMATCH`, human review |
| D57 | **`rules/` sees ONLY `CheckOutcome` + `SignatureProof`** — never identity, images, or model scores | 6 | Makes the AI boundary structural: the decision layer physically cannot consult an AI output |
| D58 | **`SIGNATURE_INVALID` → TAMPERED; `TRUSTSTORE_EMPTY`/`CERTIFICATE_EXPIRED` → ERROR** | 6 | Both give `valid=False`. Conflating them accuses an employee of forgery over our own missing certificate |
| D59 | **`ERROR` means OUR fault only**; a rejected upload is `UNREADABLE` | 6 | `ERROR` tells the employee to wait. Telling someone to wait for a fix that is never coming is worse than useless |
| D60 | **`file_validation` FAIL is checked BEFORE `qr_decoded`** | 6 | If no image was accepted we never looked for a QR — "could not read the QR" would be untrue and misdirect the retry |
| D61 | **Privacy runs ONCE at the boundary, not inline** | 6 | Scattered minimisation fails the first time a new code path forgets it |
| D62 | **`reference_id` → salted HMAC, then destroyed** | 6 | It is the closest thing to a stable per-person identifier in the QR. Per-deployment salt stops cross-tenant correlation |
| D63 | **Placeholder `hash_secret` raises at construction** | 6 | The reference-ID space is small and structured; a guessable key makes the hash brute-forceable |
| D64 | **Address and photo are dropped unless explicitly requested** | 6 | An Aadhaar address is a home address; the photo is biometric-adjacent. Neither is needed by default |
| D65 | **Document-level time budget, shared FAIRLY across sides** | 6 | Measured: a QR-less side burns ~8 s. First-come-first-served lets a bad front starve a good back — and the QR is usually on the side uploaded second |
| D66 | **`DocumentVerifier.verify()` never raises** | 6 | An exception leaves the employee with no message and HR with no record |
| D67 | **The API returns `202` and the caller polls; it never blocks for the verification** | 7 | A document takes 7–12 s. Holding the connection means client timeouts, retries that multiply the work, and one slow document occupying a request slot |
| D68 | **`JobQueue` is a Protocol; the default backend is in-process** | 7 | User decision 14 Aug 2026 ("Pluggable, in-process default"). No Redis, no broker, no extra container — the service works the moment it starts. ⚠ In-process **loses jobs on restart**; correct for single-instance, wrong for clustered. Step 8 makes the choice explicit in config |
| D69 | **Both a multipart route and a pre-signed-URL route** | 7 | User decision 14 Aug 2026 ("Both"). Multipart makes local testing and early Spring integration work with no object storage; URLs stop Spring holding two images in memory once S3/MinIO exists. Migrating later needs no API change |
| D70 | **`submit()` returns `(job, created)` — never infer "duplicate" from job status** | 7 | ★ Found in the Step 7 smoke test. With a free worker the job flips to `RUNNING` before `submit` returns, so `status is QUEUED` reported a brand-new job as `already_queued: true` |
| D71 | **SSRF is checked synchronously at submit, not in the worker** | 7 | ★ Found in the Step 7 smoke test. Accepting with `202` and failing later means a caller must poll to discover a *security* refusal, and every probe costs a queue slot. Now `400`, no job created |
| D72 | **`UrlCheck.blocked` separates "forbidden" from "could not tell"** | 7 | A link-local address is forbidden forever (`400`, non-retryable); a DNS timeout is transient (`503`, retryable). Collapsing both into one refusal would strand legitimate requests through a resolver blip |
| D73 | **SSRF check runs on the RESOLVED ADDRESS, and redirects are never followed** | 7 | An attacker controls their own DNS — `images.attacker.com` → `127.0.0.1` defeats any hostname check. A `302` to the metadata endpoint defeats the check just as easily |
| D74 | **`_is_forbidden_address` orders reasons most-specific-first** | 7 | `0.0.0.0` is unspecified *and* private; `169.254.169.254` is link-local *and* private. Outcome is identical, but the log line should name the real problem |
| D75 | **`/ready` fails (503) on an empty trust store; `/health` stays 200** | 7 | Without a certificate every genuine document returns `ERROR`. The service is up and useless, and only it knows — a load balancer cannot infer that. `/health` answers "restart me?", `/ready` answers "send me work?" |
| D76 | **The service starts with an unusable trust store rather than refusing to boot** | 7 | A pod that will not start stalls a rollout with no visible reason. An unready pod is diagnosable from outside |
| D77 | **The queue is bounded (`503` + `Retry-After`) and results expire (15 min TTL)** | 7 | An unbounded queue hides overload instead of preventing it; retained results are an unbounded leak in a long-running process |
| D78 | **Counters are mutated under a lock** | 7 | ★ Found in the Step 7 smoke test. `d[k] = d.get(k, 0) + 1` from worker threads is a read-modify-write; a metric that silently undercounts is worse than no metric |
| D79 | **★ The working image is sized and CROPPED relative to the located QR, not to a pixel cap** | 7.5 | THE bug behind the 22.7% real-world decode rate. `working_max_edge` was 4000 and phone photos are 4032px, so nothing was ever downscaled. Measured cost per variant on a 12MP frame with no readable QR: 0.82s generate + **1.81s zxing** = 2.63s. zxing is slowest exactly when it FAILS, because it searches the whole frame before giving up. At 2.63s/variant a 12s budget bought 4-6 of 23 strategies — 17 never ran, which is why every corpus success came from `original` at index 1 |
| D80 | **`ops.find_qr_region` uses finder patterns, never `cv2.QRCodeDetector`** | 7.5 | Measured: `cv2.QRCodeDetector` cannot locate even a pristine synthetic Secure QR. The finder-pattern detector agrees with zxing's own corners to within 4px |
| D81 | **Three finder marks must form a RIGHT ISOCELES triangle** | 7.5 | Without the geometry constraint, ordinary card furniture produced "QR" boxes covering 91% of the frame. False positives here are worse than misses — they send the crop to the wrong place |
| D82 | **Localisation runs on a 1400px scout copy** | 7.5 | Searching a 12MP frame costs ~1s; the scout costs ~0.1s and finds the same patterns, which are large features |
| D83 | **"No QR located" is a FAST-FAIL signal** | 7.5 | Measured across the degradation matrix: `find_qr_region` never missed a QR that zxing could read, and found codes at 57px that zxing could not. So nothing located means nothing to decode — cap hard and fail in seconds rather than spending 50s proving a negative |
| D115 | **★ The QR is decoded IN THE BROWSER before upload** | 11 | THE fix for the decode rate. Step 7.5 made the server 5x faster and the 22.7% did not move, because the failures were captures that could never work — 0/8 of the 2.3MP (chat-app compressed) images decoded, vs 5/14 at 12.2MP. No server work invents absent information. If the browser can read the code the server will too; if not, the person is told in ~50ms with the camera still open instead of after an 8s round trip |
| D116 | **⛔ The browser pre-check is NEVER a verdict** | 11 | `PrecheckResult` has no `verified` or `signatureValid` field and a test asserts it never gains one. Same boundary as the AI layer (§7): things that improve INPUT may be fast, approximate and client-side; the thing that decides authenticity may not. The decoded payload also never leaves the device — only its length is used |
| D117 | **⛔ The browser NEVER calls AVS directly** | 11 | Calling AVS requires an HMAC signature and a browser cannot hold a secret — anything shipped to a client is public. Images go to the HRM, which signs server-side. A "simplifying" refactor here would put the tenant key in a JS bundle |
| D118 | **Capture thresholds come from the Step 7.5 corpus, not intuition** | 11 | `MIN_MEGAPIXELS = 4` because every 2.3MP image failed; `PX_PER_MODULE.unrecoverable = 2.0` because nothing below it was recoverable by any strategy; `MIN_SHARPNESS = 20` because the phone-a-dim shots at 6.7-11.7 never decoded. Camera requests 3840px ideal, JPEG quality 0.95 not 0.8 — artefacts land exactly on QR module edges |
| D119 | **A MARGINAL QR warns but does not block** | 11 | Blocking would turn away someone about to succeed: if the browser already decoded it, the server will too. Likewise when no detector is available (Safari without the optional WASM), upload proceeds — refusing because OUR accelerator is missing would lock those users out entirely |
| D157 | **★★★ A LEGACY QR ON PAGE 1 ENDED THE SEARCH — found by the first three real e-Aadhaar PDFs** | 11b | `_process_side` returned at the first page that decoded ANYTHING. A real e-Aadhaar carries more than one QR (a small legacy or address-slip code as well as the signed Secure QR, often on different pages), so a legacy code on page 1 stopped the search and the Secure QR on page 2 was never reached. Verdict: `LEGACY_FORMAT` — "this is an older Aadhaar, download a fresh one" — for a **current** card, which is advice the employee cannot act on: downloading again produces the same PDF and the same wrong answer. ⚠ **No test could have caught this.** Every synthetic fixture had exactly one QR; the whole 800-test suite passed while the first three real documents failed. Fixed: stop only on `PayloadKind.SECURE_QR`, and rank the fallbacks (legacy > foreign > nothing) so the most actionable message still survives when no Secure QR exists. Regression test verified to FAIL on the old condition with the identical `LEGACY_FORMAT` |
| D152 | **★ Step 10's Spring layer DELETED — the schema kept** | 11b | User decision 20 Aug 2026. Once the Next.js route signs and calls AVS directly, the Java HTTP client, HMAC signing, controllers and entities had no caller — 10 files, ~1,200 lines, deleted. ⚠ **`V1__aadhaar_verification.sql` was NOT dead** and moved to `migrations/001_aadhaar_verification.sql`: it carries the two CHECK constraints from D113, which nothing else in the system enforces and which apply whichever language writes the rows. The D110 interop proof also survives — `lib/avsSignature.test.ts` carries its own six vectors verified against the Python service, so deleting `AvsSignatureTest` lost no coverage. D111 remains true and now describes `lib/avsSignature.ts`; re-measured in TypeScript against a live auth-on service: FormData → 401, hand-built Buffer → 202 |
| D153 | **⛔ Deleting Spring removed the only PERSISTENCE — nothing recorded a verification** | 11b | Not noticed until the deletion was surveyed. With the browser polling a Next.js route, an approved result was returned and then evaporated: no HR record, no review queue, and no store for Step 18's duplicate detection to join on — which would have made `DUPLICATE`, one of the nine verdicts, permanently unreachable. Fixed by `lib/verificationStore.ts`, written from the poll route. ⚠ The lesson generalises: "these files are unused" was true of the code and false of what the code was *for* |
| D154 | **Only APPROVED verifications are stored** | 11b | User requirement 20 Aug 2026: real → HRM DB, everything else → re-upload message. Failed attempts and the identity data inside them therefore never accumulate, which is a privacy win rather than a shortcut. ⚠ The schema keeps its review columns anyway: `PROFILE_MISMATCH` needs expected identity at submit time, `TEXT_MISMATCH` needs Step 17 and `DUPLICATE` needs Step 18 — none reachable yet, but adding the columns later would be a migration against live identity data |
| D155 | **Records are written on POLL, not from the AVS callback** | 11b | The callback is more robust — it lands even if the employee closes the tab — but it is the most security-critical endpoint in the integration, and adding that attack surface for a 1-2 second window is a poor trade. A missed write is self-healing: the employee re-uploads and it verifies again. ⛔ Idempotent on `job_id` (`ON CONFLICT DO NOTHING`) because polling reaches this code once per poll after completion, and a refresh restarts polling — without it one verification would produce several rows in the table Step 18 joins on |
| D156 | **⛔ A storage failure must never become a verification failure** | 11b | The cryptography has already succeeded by the time the write is attempted; the card IS genuine. Letting a database outage surface as "your Aadhaar could not be verified" would blame the employee's document for our infrastructure — exactly the confusion CONTRACTS.md §1 exists to prevent. The write is wrapped, logged loudly for operators, and the employee is still told the truth |
| D149 | **★★ CROPPING RECOVERS NOTHING — and my first reading of this was WRONG** | 14 | Reported initially as "2 of 6 crops decode that the pipeline failed on", implying 30% → 37%. **False.** `--compare-pipeline` showed the 2 images whose crops decode are EXACTLY the 2 the full pipeline already decodes; the folder was never 6 failures, it was 4 failures and 2 successes — a number already printed by the corpus run ("phone-b-good-light 2/6") and misread anyway. Decodes recovered by cropping: **0**. The consequence matters: the localiser already finds these codes, crops them at full resolution, and they still fail at 1x, 2x and 4x. So **Step 15 (better localisation) would not help** — the codes are genuinely unreadable, which is Step 19 (restoration) territory |
| D148 | **★★ MY OWN DIAGNOSTIC USED THE WRONG DECODER, AND TOO LITTLE PADDING** | 14 | `diagnose_failures.py` judged crops with `cv2.QRCodeDetector` — the detector whose inability to read a dense Secure QR is the documented reason `find_qr_region` exists at all. It also padded crops by only 10%. Measured on a known-good 700x700 QR: the localiser reports 512x581 (the box spans finder-pattern CENTRES, so it is always smaller than the code), and cropping to it fails at 10% and 25% padding but **decodes at 50%**. So "the crop decodes at NO scale" was measuring my harness, not the image. Now uses the real cascade and 50% padding. ⚠ Production was never affected — Step 7.5's generator already pads 60% (`qr_context`) |
| D144 | **★★★ THE BROWSER WARNED ABOUT PHOTOS THE SERVER DECODED** | 14 | `MIN_MEGAPIXELS = 4` was hand-set in Step 11 from a 22-image corpus where "every 2.3 MP image failed" was true. The corpus grew to 27 documents and the weakest capture that ACTUALLY DECODED now measures **2.31 MP** — so the browser flagged as unusable a photo the server reads perfectly. The two threshold sets were never connected, so nothing noticed. Fixed by generating `thresholds.generated.ts` from `assessor.py` via `scripts/export_thresholds.py`, with tests on both sides that fail on drift. Two vitest tests asserted the old value and were reversed |
| D145 | **Sharpness is deliberately NOT synced to the browser** | 14 | The server floor is an OpenCV variance-of-Laplacian figure. The browser computes no sharpness at all (`FrameMeasurements.sharpness` is optional and no caller supplies it), and a JavaScript Laplacian would not share OpenCV's scale. Copying 250 across would be a number that looks authoritative and means nothing — worse than an obviously unused constant, because it reads as a decision that was made and tested |
| D146 | **★ Darkness outranks blur when both fire — measured** | 14 | Laplacian variance scales with CONTRAST, so a perfectly focused photo taken in the dark measures as blurry. On one image at decreasing exposure, focus untouched: brightness x1.00 → sharpness 1315, x0.35 → 155, x0.12 → 22. Darkness CAUSES the low reading, so "hold steadier" sends someone to fix the wrong thing and they fail again identically. More light fixes both |
| D147 | **`_refine_message` returned before quality could run** | 14 | The guard read `if self.classifier is None`, written when the classifier was the only advisor. Step 14 added quality, and since D135 retired the classifier the DEFAULT configuration has none — so the measured component was silently dead in the normal case. Also fixed `_classifier_name`, which recorded "NoneType" in `AiTrace`; "which model produced this?" is the first question asked when a result looks wrong |
| D141 | **★★★ QUALITY REORDERS THE VARIANT MATRIX — it must never shrink it** | 14 | `select_strategies` FILTERED on detected problems, and Step 14 was about to switch that on. Measured: when quality reports "this photo looks fine", **23 strategies became 3** — and among the 20 discarded was `gray+adaptive`, the only strategy that rescued a heavily blurred card the original failed on (attempt 6). The four real corpus images that are sharp, bright and well-sized yet undecodable are exactly the inputs quality calls fine, so filtering would have stripped their best remaining chance on the images needing it most. Now reorders only; tier stays the primary sort key so cheap-before-expensive still wins. Two existing tests asserted the old behaviour and were reversed |
| D142 | **The preprocessing variants DO earn their place — cutting them was the wrong instinct** | 14 | All 8 corpus successes decoded on `original`, which suggested the 18 variants were dead weight costing 4.3s per failure. Tested directly on degraded cards: `blur 21` failed on the original and was **rescued by `gray+adaptive` at attempt 6**. 1 of 2 genuinely-hard cases recovered. The matrix stays; only its order is optimised |
| D143 | **`problems_from_quality` no longer reports every problem on low decodability** | 14 | It had `if decodability < 0.5: problems.update(Problem)` as a safety hatch against filtering. With filtering gone that safety is structural, and the hatch became harmful: marking everything as detected made every strategy equally relevant and produced an ordering **byte-identical** to having no quality model. Measured on blur, glare and no-quality inputs — all three orderings matched exactly |
| D137 | **★★★ `find_qr_region` HAD TWO BUGS — every px_per_module was inflated ~3x** | 14 | Found by diagnosing 6 "perfect but failing" captures: all 6 located regions failed to decode even cropped and upscaled 4x, and 5 of 6 were **non-square** — one at aspect 0.51 (2788x5417). A QR is square. Root causes: (1) the finder-pattern geometry check required legs `> 1.5 x marker width` when real QR geometry gives **12.9x** for Aadhaar's version 21-22 — about 9x too loose, so any three marks on a card qualified; (2) it kept the **largest** matching candidate, so a phantom spanning the whole card always beat the real QR. Fixed with a squareness guard, a `MIN/MAX_LEG_TO_MARKER` window from QR geometry, and selection by **finder-pattern size** — "smallest box" was tried and broke real detection (86x86 returned for a 700px code). Shipping since Step 7.5 |
| D138 | **The localiser fix did NOT raise the decode rate — and that is the finding** | 14 | Prediction was that correct cropping would unlock decodes. It did not: 8/27 before and after. Since cropping accurately to the QR changes nothing, "the code is too small in the frame" is ruled out as a cause. The remaining failures are intrinsic to the QR image — blur, glare, print quality. Measurements did become physically plausible (px/module range 1.90-42.7 -> 0.44-16.89, matching the 12.9 predicted by card geometry) and phantom detections fell 16/19 -> 11/19 |
| D139 | **Quality thresholds come in TWO sets, because false alarms cost differently** | 14 | `POST_FAILURE` sits at the measured floor (sharpness 368.76, brightness 108.73) — it runs on an image that has ALREADY failed, so a false alarm is impossible by construction. `PRE_UPLOAD` sits ~30% lower (250, 80) because it runs in the browser before the photo has had its chance, where a false warning costs a real person a pointless retake. Coverage drops 68% -> 58%; correct trade |
| D140 | **`px_per_module` is measured but NOT used as a rule** | 14 | Combined-coverage analysis: sharpness catches 68%, brightness a further 11% (79% total), px_per_module adds **zero** — every image it catches is already caught. A rule that never fires alone is code with no reason to exist, so it is reported and not acted on |
| D135 | **★★★ THE HEURISTIC CLASSIFIER IS RETIRED — it caught 0 of 19 real wrong-uploads** | 13 | Measured against 19 genuine mistake-uploads (screenshots, UI mockups, keyboard, desk, sunset, face, waveform): **0 caught**. Feature ranges — documents edge 0.0000-0.1232 / brightness 41.0-174.6, negatives edge 0.0031-0.0886 / brightness 3.7-235.2. The negative range sits **entirely inside** the document range on edge density: 100% overlap, so no threshold separates them and tuning cannot help. Reason in one line: a screenshot of text IS a document image, just not an Aadhaar one — shape statistics describe STRUCTURE, and telling an Aadhaar from a PAN needs CONTENT. `build_classifier()` now defaults `allow_heuristic=False`; the class is kept as the reference implementation and for diagnostics, not deleted |
| D136 | **`find_qr_region` false-positives on UI screenshots** | 13 | Five of the 19 negatives were swallowed by "a QR or document quad was detected". Screenshots contain concentric rounded squares — icons, buttons, cards — that look like QR finder patterns. **Harmless in preprocessing** (Step 7.5 always offers the uncropped frame as a fallback variant, and real cards decode 5/5), but it means QR-presence is not usable as evidence of "this is an Aadhaar". Relevant to Step 15's localiser: it must be scored against negatives, not only against cards |
| D134 | **`avs classify` accepts a FOLDER, because a documented placeholder is not a path** | 13 | The command demanded one filename, so documenting it required writing `<pick any file>`. Pasted verbatim, PowerShell split it on spaces and typer said "unexpected extra argument (any file in that folder>)" — an error naming neither the cause nor the fix. Taking a folder removes the filename from the interface entirely: nothing to guess, nothing to paste wrongly. A placeholder-shaped argument is now detected by name and answered with the working command |
| D132 | **★★ REAL DATA KILLED THE EDGE TEST — exposure gating added** | 13 | Ran `collect_classifier_features.py` on the 22-image corpus. `phone-a-dim` measured **0.0000 / 0.0019 / 0.0096** edge density — genuine Aadhaar cards, AT AND BELOW the 0.005 floor, indistinguishable from a blank frame. Underexposure destroys edge structure, so the two classes overlap completely at the low end — the opposite of what generated data implied. They escaped misclassification only because the QR/quad check fired first, which is luck, not margin. `NOT_A_DOCUMENT` now additionally requires `mean_brightness >= 60`; a dark frame is an EXPOSURE problem and "photograph it in good light" is already the right advice |
| D133 | **★★ MY SAFETY CHECK PASSED BY MATCHING NOTHING** | 13 | The script's misfire check filtered documents with `"aadhaar" in label or "id" in label`. The real folders are `phone-a-dim`, `phone-b-angled`, `scanner` — it matched **zero rows**, so "weakest real document" never printed and the check compared against an empty set and printed ✓. Three cards were below the threshold at the time. **A green tick from a check that found nothing is worse than no check**, because a human then trusts it. The default is now inverted: everything is a document unless a folder name explicitly says otherwise, the assumption is printed, and an empty document set is reported as proving nothing |
| D127 | **★ High edge density is NOT evidence of a document** | 13 | The obvious heuristic — "documents are dense with text, so lots of edges means a document" — is false. Measured: a brick wall and random noise both score 0.104 edge density; a real card scores 0.042. **The wall is twice as document-like on the obvious feature.** Only the LOW end survives: near-zero edges, no quad and no QR means no document. Everything else is UNKNOWN |
| D128 | **⛔ The classifier refines the MESSAGE, never the verdict** | 13 | It runs after `rules.decide()` returns, only when the verdict is UNREADABLE, and writes only `user_message` and `ai_trace`. A VERIFIED document is never classified at all — so no model output exists that would have to be correctly ignored. `test_classify_never_changes_verdict.py` feeds the pipeline a classifier returning EVERY DocType at confidence 1.0 and asserts verdict, proof, error and checks are identical to the no-classifier run |
| D129 | **The heuristic claims exactly one thing, and says UNKNOWN to everything else** | 13 | It never returns AADHAAR_FRONT/BACK/PVC/OTHER_ID — telling a front from a back, or an Aadhaar from a PAN, needs a trained model. Shipping a confident-sounding guess would be worse than shipping nothing, because UNKNOWN changes no behaviour while a wrong specific answer sends someone off to fix the wrong problem |
| D130 | **Refinement requires UNANIMITY across sides** | 13 | One clear card photo plus one photo of a thumb is a CAPTURE problem, and "retake in good light" is the correct advice there. Saying "these do not appear to show a document" to someone who photographed their card correctly once would be both wrong and insulting |
| D131 | **Thresholds set from generated images are provisional and labelled as such** | 13 | `EDGE_DENSITY_FLOOR` sits ~7x below the weakest generated document rather than midway between classes, because generated non-documents measure exactly 0.0000 — a figure no real photograph produces. The asymmetry is deliberate: a false NOT_A_DOCUMENT tells someone their genuine card is not a card, while a miss costs only the message already shown today. `scripts/collect_classifier_features.py` produces the real numbers, emitting shape statistics only |
| D120 | **⛔ A model must never be able to fail a verification** | 12 | The single rule `ModelRunner` exists to enforce. Absent model, absent `onnxruntime`, failed digest, throwing graph, hanging graph, empty output — all six end in `None`, meaning carry on deterministically. Before this, "AI is optional" was a convention each of the five AI modules had to honour separately, which is five chances to get it wrong |
| D121 | **Models are SHA-256 pinned, exactly like UIDAI certificates** | 12 | An ONNX graph is executable content interpreted by onnxruntime — it can carry custom operators, and a hostile one attacks the process that loads it. Dropping a file into `models/` is closer to dropping a `.so` into the library path than to editing config. `models.json` pins each digest; a mismatch is refused before onnxruntime sees the file |
| D122 | **An EMPTY model registry is a healthy state, not a warning** | 12 | `avs models status` exits 0 with nothing declared. Treating "no models" as a failure would invert the relationship the whole AI boundary rests on — the accelerator would have become the dependency, and a missing accelerator would stand between a person and their verification |
| D123 | **A slow model is ABANDONED, not waited for** | 12 | Inference runs on a daemon thread with `join(timeout)`. Python cannot safely kill a thread executing native code, so the thread is abandoned and its result discarded. A leaked thread for a few hundred ms is survivable; a hung verification consuming the 12s document budget — while the deterministic path was going to succeed anyway — is not |
| D124 | **The AI boundary is now enforced in BOTH directions** | 12 | Steps 0–11 asserted the decision layer never imports `avs.ai`. Step 12 adds the reverse: no `avs.ai` module may import `crypto`, `rules`, `truststore` or `parser`. This is the more likely accident — the natural shape of "I just need a bit more context here" is an import, and a model that can see a signature is one refactor from influencing it. Plus a type-level guard: `InferenceOutcome` may never gain a field an approval could be read from |
| D125 | **★ `CONTRACT_VERSION` is now read from CONTRACTS.md, not pinned as a literal** | 12 | Found during Step 12: the test asserted `== "1.3.0"` and passed happily while the document advanced to 1.7.0 — four steps of drift, with `avs version` reporting a contract version that had not existed for weeks. The same failure shape as the Step 7.5 `"V2"` bug: **a test that pins a literal proves only that the literal has not changed.** The test now parses the document, so the two cannot separate |
| D126 | **★ `models pin` refuses a file that cannot be a model** | 12 | Found by running the command: a 0-byte file was pinned, printing the SHA-256 of zero bytes. The digest was valid, so every downstream check would have passed and `models status` would have shown `pinned ✓`. Pinning answers "is this the file we chose?", never "is this a model?" — the gap has to close at the CLI, the one point a human reads the values before committing them |
| D110 | **★ Java/Python HMAC interop is PROVEN, not assumed** | 10 | Six shared vectors compared byte-for-byte: JSON body, empty body, both halves of the canonicalisation-collision pair, a BINARY multipart body, and a non-ASCII secret. A mismatched canonical string is the classic silent integration failure — everything looks right and every request 401s. The real vector is pinned in `AvsSignatureTest` |
| D111 | **`AvsClient` builds the multipart body BY HAND** | 10 | The signature covers the exact bytes on the wire. Any library that regenerates the body — different boundary, header order or line endings — produces bytes that no longer match, and the symptom is an unexplained 401. Verified: a Java-built 305,998-byte request produced `VERIFIED` from the live Python service in 3.3s |
| D112 | **⛔ The callback endpoint verifies the HMAC over the RAW body, BEFORE parsing** | 10 | THE most security-critical file in the integration. An unsigned callback endpoint lets anyone POST `{"verdict":"VERIFIED"}` and approve a forged Aadhaar — bypassing the RSA check, the pinned trust store and the audit trail with one request. Raw bytes because Jackson normalises key order and whitespace; before parsing because running a parser on attacker-controlled input precedes establishing who sent it |
| D113 | **⛔ Rule 1 is enforced by a DATABASE CHECK CONSTRAINT** | 10 | `CHECK (verdict <> 'VERIFIED' OR signature_valid = TRUE)`. Documentation can be forgotten and application code can be bypassed by a migration or a manual UPDATE; the constraint cannot. Likewise `aadhaar_last4 ~ '^[0-9]{4}$'` makes storing a full Aadhaar number fail the INSERT rather than succeed quietly |
| D114 | **Per-tenant CALLBACK secret, separate from the inbound key** | 10 | Different key per direction, so a compromised inbound secret cannot forge results back to the HRM. `TenantConfig.outbound_secret` falls back to the inbound key when unset — better practice without forcing it on an integrator who has not asked |
| D103 | **⛔ The audit trail is hash-chained, not merely appended** | 9 | A plain log can be edited: someone with write access deletes the entry showing a rejection, or adds one showing an approval, and the file looks fine. Each entry carries the SHA-256 of the previous one, so any edit, deletion, insertion or reorder breaks every hash after it. It does NOT prevent a wholesale rewrite — that needs an append-only store, and `AuditSink` is a Protocol so one can be added — but silent PARTIAL tampering becomes impossible, which is the realistic threat |
| D104 | **Both self-consistency AND linkage are checked** | 9 | A careful attacker edits an entry and re-hashes it, defeating the self-check. The following entry still points at the old hash, so the linkage check fires. Either alone is bypassable; together they are not |
| D105 | **⛔ The audit trail carries NO personal data** | 9 | Step 8 established that AVS never persists Aadhaar data; this trail is the single exception, so the rule is tightest here. Verdicts, timings, certificate serials and a salted reference hash only. `test_audit.py` asserts the entry has no field that could hold a name, DOB, address, image or any part of an Aadhaar number |
| D106 | **★ `avs_decode_rate` is instrumented in production** | 9 | The project's PRIMARY metric existed only in `scripts/corpus_report.py`. That is precisely how a real-world decode rate of 22.7% went unnoticed while 540 tests passed green. Also exports which decoder and which preprocessing strategy actually rescued each document — on the real corpus every success came from `original` until the Step 7.5 fix, and a regression there would otherwise be silent |
| D107 | **A restart continues the existing chain rather than starting a new one** | 9 | Two chains in one file is indistinguishable from tampering. `FileAuditTrail` reads the last hash from disk on first use |
| D108 | **Request correlation ids are bound into the log context and cleared in `finally`** | 9 | One document touches ingest, imaging, decode, parse, crypto and rules, interleaved with every concurrent document. Without a shared id, investigating a complaint is guesswork. The unbind is not optional — context vars outlive a request in a thread pool, so a leaked id puts one request's identifier on another's logs, which is worse than none |
| D109 | **`avs certs pin` closes the trust-store poisoning gap** | 9 | Flagged twice in Steps 7 and 8 and left open. A certificate in `certs/` is a licence to mint approvals. Pinning state is now on `/ready` and in `avs_certificate_pinning`, so it shows in a dashboard rather than only a startup log |
| D97 | **⛔ Every `/v1` route requires an HMAC signature; probes stay open** | 8 | User decision 14 Aug 2026. Step 7 shipped with NO authentication — anything reaching the port could submit a document and get a verdict. HMAC over `timestamp.nonce.body` rather than a static API key, because a bearer token is replayable forever and a key leaked into a proxy log stays valid until someone notices. Same construction as the Step 7 callback dispatcher, so the HRM implements one scheme both ways |
| D98 | **The 401 body is identical for every failure cause** | 8 | Distinguishing "unknown tenant" from "bad signature" from "replay" is an oracle for enumerating tenants and probing the scheme. Unknown tenants also run a dummy HMAC so the response time does not leak membership |
| D99 | **The nonce is remembered only AFTER the signature verifies** | 8 | Otherwise an attacker who can observe or guess a nonce pre-registers it with a garbage signature and the legitimate request is rejected as a replay |
| D100 | **★ `BodyBufferMiddleware` — the auth work nearly broke every file upload** | 8 | An ASGI body is a one-shot stream and FastAPI parses a multipart form BEFORE solving dependencies, so `request.body()` in the auth dependency raised "Stream consumed". JSON routes were fine; **only multipart broke — the route the HRM actually uses.** Caching on the Request is insufficient because the handler builds its own Request from the same scope. The body is now buffered once before routing and `receive` replays it. Bounded at 32 MB — an unbounded buffer is a memory-exhaustion primitive |
| D101 | **⛔ AVS NEVER PERSISTS AADHAAR DATA** | 8 | User decision 14 Aug 2026: images live in the HRM's database. So AVS holds no bucket to leak, no retention policy to get wrong, no purge job to fail silently, and a compromised host yields nothing historical. Enforced, not documented: `tests/unit/test_statelessness.py` runs a full verification with every filesystem write intercepted and fails if image bytes or a payload reach disk. It does **not** claim RAM zeroisation — that would be a lie in pure Python |
| D102 | **Tenant secrets come from the environment; the registry file holds only the variable NAME** | 8 | The registry is then safe to commit and safe in a ConfigMap. `TenantConfig` refuses empty, short (<32 char) and placeholder secrets **at construction** — a service running with `changeme` as a signing key looks healthy right up until someone tries it |
| D93 | **⛔⛔⛔ THE ROOT CAUSE OF THE WHOLE STEP-7.5 BUG HUNT: the test fixture shared the parser's assumptions** | 7.5 | `SyntheticQrBuilder` emitted a leading `"V2"` marker. `FIELD_MAPS["V2"]` expected one. **UIDAI's specification contains no such field.** Fixture and parser agreed with each other and both disagreed with every real card — which is why 540 tests passed while real Aadhaar failed. A fixture derived from the same understanding as the code under test proves only self-consistency. Fixture default is now `version=None`, the real layout |
| D94 | **`FIELD_MAPS["V1"]` is transcribed verbatim from UIDAI's spec** | 7.5 | UIDAI "SECURE QR CODE SPECIFICATION" March 2019 §3.1. The address order is care_of, district, landmark, house, location, pincode, post_office, state, street, sub_district, vtc — **not** the logical postal order a developer would invent. Guessing it would put the district in the house column on every card, and the signature would still verify because it covers raw bytes |
| D95 | **★ Field-map selection is SELF-CORRECTING, not a sniff of field 0** | 7.5 | The two layouts differ by one leading field, so picking between them by inspecting field 0 is fragile: any noise there shifts EVERY field and surfaces far away as "reference_id does not start with 4 digits". Now tries the detected map, then the other, and accepts whichever yields a valid `reference_id` (4 digits + DDMMYYYYHHMMSSsss). Cannot weaken security — the signature covers raw bytes and is unaffected by field labelling |
| D96 | **UIDAI's published sample payload is a permanent regression test** | 7.5 | `tests/unit/test_uidai_spec_conformance.py`. The only test in the suite whose input is independent of our own assumptions. NOT committed — it decodes to a real person's demographics and photo; `scripts/fetch_spec_sample.py` retrieves it into a git-ignored path and the sample tests skip without it |
| D91 | **⛔⛔ Secure QR text fields are ISO-8859-1, not UTF-8** | 7.5 | FOUND ON REAL CARDS. `_split_fields` decoded each chunk as UTF-8 and **broke out of the loop** on `UnicodeDecodeError`, with a comment claiming it had reached the binary photo block. Wrong: a text field can fail UTF-8 simply because it is not UTF-8. Any name containing a byte above 0x7F killed the FIRST field and surfaced as "no delimited fields found" — on a payload that had gunzipped perfectly and contained 46 delimiters. **3 of 5 successfully decoded real cards died here; only pure-ASCII names survived, which in India is a minority.** Now falls back to ISO-8859-1, which cannot raise. The binary tail is detected structurally via `_looks_like_photo`, never by guessing from a decode failure. Verification is unaffected — the signature is over raw bytes |
| D92 | **A multi-candidate parse reports the FIRST candidate's error** | 7.5 | The leading-zero retries (D88) are long shots that fail with noise. Reporting the last error turned "expected 16 fields, found 8" into a generic "malformed" — the same class of misdirection that cost days on this project |
| D89 | **⛔⛔ Certificate EXPIRY MUST NOT decide authenticity** | 7.5 | Checked UIDAI's live certificate page 14 Aug 2026: the Offline-eKYC / Secure-QR list holds **one unexpired certificate (03 Feb 2029) against five lapsed ones**, and the separate Secure-QR sub-table is entirely expired (2020, 2021). An e-Aadhaar keeps the signature it was issued with forever, so requiring a currently-valid anchor would report **every card issued before the last rotation as TAMPERED** — a false accusation of forgery against the majority of genuine cards, and a direct breach of §1 Rule 2. The signature is a fact about the past; expiry is a fact about today. Only the first decides the verdict. Expiry is still surfaced via `SignatureProof.certificate_expired`, trust-store health, `/ready` and the renewal metric. Four existing tests encoded the old (wrong) rule and were revised with rationale rather than deleted |
| D90 | **ALL historical UIDAI certificates stay in the trust store** | 7.5 | Follows from D89. Removing a lapsed certificate silently makes every document signed under it unverifiable |
| D88 | **⛔ Leading zero bytes are recovered by trying candidate byte-lengths** | 7.5 | The Secure QR is one huge decimal integer, and `int()` cannot preserve a leading `0x00`. Losing one shifts `signed_bytes = payload[:-256]`, the signature no longer matches, and a **GENUINE Aadhaar is reported TAMPERED** — the single worst failure this system can produce. We cannot know how many zeros were lost, so we try minimal, +1 and +2. This does NOT weaken security: every candidate is verified independently against UIDAI's key and a forgery fails all of them (locked by `test_leading_zero_recovery_does_not_accept_a_forgery`) |
| D85 | **★ The uncropped frame is ALWAYS offered as variant 2 when we crop** | 7.5 | The QR-relative crop made the pipeline 5x faster and immediately cost a real decode: `phone-b-angled` went 1/6 -> 0/6 because a mislocated box discarded a QR that decoded fine from the untouched frame. Speed is never worth losing a verification. One extra decode buys immunity |
| D86 | **"Decode rate" and "usable rate" are different numbers and must be reported separately** | 7.5 | The corpus showed 5/22 decoded — but 3 of those 5 failed to PARSE. The rate of images yielding usable data was 2/22 = 9%, less than half the headline. A metric that counts unparseable payloads as successes will hide a broken parser |
| D87 | **Parse failures report the MESSAGE, not just the ErrorCode** | 7.5 | `PAYLOAD_MALFORMED` has five distinct causes — not an integer, gzip failure, no delimited fields, implausibly large, empty. The code alone cannot distinguish them; the message can, and carries only byte counts and reasons |
| D84 | **A diagnostic tool must self-test before reporting** | 7.5 | The first `corpus_diagnose` wrapped a broken detector in `except: pass` and reported "QR not located" for 22 images — including 5 it had just decoded. Zeros that look like findings are worse than no measurement |

---

## Open Questions

Answer before the step that depends on them.

| # | Question | Blocks | Owner |
|---|---|---|---|
| ~~Q1~~ | ~~QR payload strings from real cards~~ — **resolved**: replaced by synthetic fixtures; real-card validation now runs locally via `scripts/validate_corpus.py` | — | closed |
| ~~Q2~~ | ~~Tampered sample~~ — **resolved**: `SyntheticQrBuilder` generates tampered variants deterministically | — | closed |
| Q1b | Run `scripts/validate_corpus.py` against real cards and send the **summary only** | confirms Step 1 field map | Dheeraj |
| Q1c | Download UIDAI certificates into `certs/`, verify fingerprints, enable pinning | real verification | Dheeraj |
| Q3 | Image corpus, 50–80 photos — **start collecting now** | Step 5, Step 12 | Dheeraj |
| Q4 | Queue backend — Celery+Redis or Kafka? | Step 7 | Dheeraj |
| Q5 | S3 or self-hosted MinIO? | Step 8 | Dheeraj |
| Q6 | Deployment target — K8s / ECS / Docker Compose / VM? | Step 8 | Dheeraj |
| Q7 | M-One database type and version | Step 10 | Dheeraj |
| Q8 | Spring Boot + Java versions | Step 10 | Dheeraj |
| Q9 | How M-One identifies tenants (column / schema / database per tenant) | Step 10 | Dheeraj |
| Q10 | Next.js version and router type; design system | Step 11 | Dheeraj |
| Q11 | Target languages for the multilingual assistant | Step 21 | Dheeraj |

---

## Deviations from the Architecture Document

None.

*Record any intentional divergence here with its reason, so future steps understand
why the code differs from `AVS_AI_Powered_Architecture_v2.md`.*

---

## Step Log

### Step 0 — Foundation & Contract Freeze · ✅ 13 Aug 2026

**Built**
- Repo scaffold: 27 module packages, each stubbed with its architectural contract
  recorded in its docstring (step, provides, consumes)
- `CONTRACTS.md` v1.0.0 — verdicts, checks, error codes, field names, the signature
  invariant, module interfaces, the AI boundary, API schema, input rules, logging rules
- `contracts/` — 7 enums, 24 domain models, 15 Protocols
- `logging/` — structlog with mandatory PII redaction in the processor chain
- `config/` — pydantic-settings with limits mirroring CONTRACTS.md §9
- `cli.py` — `avs version` · `avs contracts` · `avs doctor`
- CI: ruff, mypy strict, pytest, contract conformance, and a guard that fails the
  build if Aadhaar data is ever committed
- `.gitignore` blocks corpus directories; pre-commit blocks private keys and large files

**Tests: 46 passing**
- 16 contract conformance — verdicts, checks, errors, identity, approval safety
- 3 AI boundary — AST-level proof that decision modules never import `avs.ai`
- 27 redaction — patterns, mappings, nested structures, processor behaviour

**Verified**
- `ruff check` clean · `ruff format --check` clean · 46/46 tests green
- CLI smoke-tested: `avs contracts` renders the frozen surface correctly

**Notes for later steps**
- `imaging/` must accept an optional `QualityScores` — the seam for Step 14 is
  already declared in `VariantGenerator`
- `qr/` must accept an optional `QrRegion` — the seam for Step 15 is already declared
- `VerdictEngine.decide()` takes only `CheckOutcome` + `SignatureProof`. This is
  deliberate: it structurally cannot see model confidences

---

### Step 1 — Cryptographic Core · ✅ 13 Aug 2026

**Built**

`parser/` — Secure QR payload parser
- `fields.py` — declarative `FIELD_MAPS` for V1 (no version marker) and V2 layouts,
  presence-indicator helpers, address/identity field split
- `payload.py` — big-integer → bytes → gzip/zlib/raw decompress → `0xFF` field
  split → photo (JPEG2000) → optional hashes → signature
- Version-dispatched field mapping; pre-2018 unsigned QR detected and named
- Structural truncation check: rejects payloads where the 256-byte signature
  block would overlap the text fields
- `errors.py` — `ParseError` carrying a contract `ErrorCode`

`crypto/` — ★ signature verification, the verdict
- `verifier.py` — RSA-2048 / SHA-256 / PKCS#1 v1.5 against the trust store
- Tries **every** certificate (rotation tolerance)
- Expiry enforcement with an opt-in `allow_expired` forensic escape hatch
- Returns `SignatureProof` in all cases; never raises for a tampered document

`truststore/` — partial (Step 2 completes it)
- `UidaiCertificate` — immutable, public-key-only, expiry helpers
- `InMemoryCertificateStore`, `load_certificate_file()` (PEM and DER)

CLI
- `avs verify-qr --file <path>` — payload read from a file, never an argument,
  so it stays out of shell history
- `avs selftest` — generates a throwaway keypair, builds a synthetic payload,
  tampers with it, and proves genuine→VALID / tampered→INVALID

Tooling
- `tests/fixtures/synthetic.py` — `SyntheticQrBuilder` producing byte-exact
  payloads plus tampering methods: field edits, byte flips, photo swap,
  truncation, signature stripping
- `scripts/validate_corpus.py` — local real-card validation that prints
  **counts and error codes only**, never personal data

**Tests: 149 passing** (up from 46)
- 48 tamper detection — 17 field edits, 12 byte-flip offsets, a 100-byte
  exhaustive sweep, photo swap, signature boundary exactness, trust-store failures
- 34 parser — layouts, hash combinations, and every documented failure path
- 21 crypto — proof evidence, rotation, expiry, legacy handling, immutability
- 46 from Step 0, all still green

**Verified**
- `ruff check` clean · `ruff format --check` clean · 149/149 tests
- `avs selftest` passes end to end

**The central claim, now demonstrated in code**
- Genuine payload → `valid=True`, repeatable across 20 runs
- Any single edited field → `valid=False`
- Any single byte flipped anywhere in the signed region → `valid=False`
  (exhaustive sweep of the first 100 bytes: zero survivors)
- Signature boundary shifted by ±1 byte → `InvalidSignature`
- Empty, expired, or wrong trust store → never approves

**⚠ Open validation item**
`FIELD_MAPS` is implemented from UIDAI's published specification and has **not**
been validated against a real card. If a real card decodes with fields in the
wrong slots, the fix is one line in `src/avs/parser/fields.py`. Run
`scripts/validate_corpus.py` locally and send the summary.

**Notes for later steps**
- `qr/` (Step 5) feeds `parser.parse()` with `DecodeResult.raw_payload`
- `rules/` (Step 6) consumes `SignatureProof.valid` — the only approval input
- `truststore/` (Step 2) replaces `InMemoryCertificateStore` with a directory-backed
  store; `SecureQrVerifier` already accepts any sequence of `UidaiCertificate`
- `ocr/` (Step 17) cross-checks visible text against `QrPayload.identity`

---

### Step 2 — Certificate Trust Store · ✅ 13 Aug 2026

**Built**

`truststore/store.py` — `FileCertificateStore`
- Directory loading of `.cer` / `.crt` / `.pem` / `.der`, PEM and DER encodings
- Deduplication by certificate serial (same cert supplied twice)
- Ordering: **newest expiry first**, so current cards match on the first attempt
- Non-certificate files silently ignored; unreadable files recorded as `LoadIssue`
- Lazy loading — `certificates()` loads on first access
- **Fingerprint pinning** via `certs/FINGERPRINTS.txt`: when present, only listed
  SHA-256 fingerprints are loaded; everything else is refused as a fatal issue
- `require_pinning=True` refuses to start at all without a pin file
- `TrustStoreHealth` — status, counts, earliest expiry, pinning state, issues,
  and `is_ready` for the Step 7 readiness probe
- `ExpiryStatus` — OK / WARNING / EXPIRED / EMPTY

`truststore/certificate.py`
- `UidaiCertificate.fingerprint_sha256` added, computed on load from the DER encoding

`truststore/errors.py`
- `TrustStoreError`, raised only for conditions that make the service unsafe to start

CLI
- `avs certs status` — table of certificates with expiry colouring, load issues,
  pinning state, health summary; `--strict` exits non-zero on any warning
- `avs certs fingerprints` — emits `FINGERPRINTS.txt` format for review
- `avs verify-qr` now uses `FileCertificateStore` and surfaces refusals

Docs
- `certs/README.md` rewritten: where to obtain UIDAI certificates, the four rules,
  the poisoning attack pinning prevents, monitoring, and why an empty store
  correctly fails closed

**Tests: 182 passing** (up from 149) — 33 new
- Loading: PEM, DER, mixed, junk files, corrupt files, duplicates, missing dir,
  empty dir, idempotency, lazy load
- Ordering, expiry classification, earliest-expiry semantics
- Pinning: accepted, refused, comments/blanks, colon-separated form,
  `require_pinning` enforcement
- Fingerprints, metadata, non-RSA rejection, garbage files
- **Rotation end-to-end**: a card signed by the previous certificate still verifies
  in a rotated store — plus the inverse, documenting the failure a single-certificate
  store would cause

**Verified**
- `ruff check` clean · `ruff format --check` clean · 182/182 tests
- `avs certs status` exercised against a demo directory containing valid,
  expiring, expired, corrupt and unpinned certificates
- Pinning demo: a rogue certificate dropped into the directory was refused

**⚠ `certs/` is still empty**
No UIDAI certificate is committed. `avs certs status` therefore reports `EMPTY`
and every verification fails — which is correct. No trust anchor, no approval.

**Notes for later steps**
- `health/` (Step 7) should surface `TrustStoreHealth.is_ready` in `/ready`
- `observability/` (Step 9) should export `days_to_earliest_expiry` as
  `avs_certificate_days_to_expiry` and alert at 90 days
- Production deployments should construct the store with `require_pinning=True`

---

### Step 3 — Ingest & Validation · ✅ 13 Aug 2026

**Built**

`ingest/magic.py` — pure-stdlib magic-byte detection
- Accepts JPEG, PNG, WebP, HEIF (ISO-BMFF brand check)
- Names disallowed types precisely: PDF, GIF, BMP, TIFF, ZIP/gzip, ELF, PE, Java
  class, SVG, HTML — each with an employee-facing message
- Never raises; unknown input returns `FileKind.UNKNOWN`

`ingest/validator.py` — `ImageIngestor`
- Ordered checks: upper size → magic → allow-list → lower size → scan →
  header read → bomb guards → decode
- Bomb guards run on **header dimensions**, before any pixel is decoded:
  max dimension, max total pixels, and a pixels-per-byte density heuristic
- Magic-vs-decoder cross-check catches parser-confusion attempts
- EXIF orientation applied, then **all metadata stripped** via a fresh canvas
- HEIF normalised to JPEG; JPEG re-encoded at quality 95 / no subsampling to
  preserve the fine QR module edges decoding depends on
- Optional `strip_metadata=False` forensic mode carries EXIF through explicitly

`ingest/scanner.py`
- `MalwareScanner` Protocol, `NullScanner`, `ClamAvScanner`
- ClamAV **fails closed** when the daemon is unreachable; `fail_open` is opt-in

`ingest/errors.py`
- `IngestError` carrying both a technical `message` and a `user_message`

CLI
- `avs ingest <file>` — detection table, accept/reject with both messages,
  `--scan` for ClamAV, `--keep-metadata` for forensic mode

**Tests: 253 passing** (up from 182) — 71 new
- Magic detection across 11 disallowed types plus short/unknown input
- Accepted formats, hashing, capture method, repr safety
- Every rejection path with the correct `ErrorCode`
- **Extension-never-trusted**: executables and PDFs renamed `.jpg` still refused;
  valid images with wrong extensions still accepted
- Decompression bombs caught before decode; real photos not falsely flagged
- **EXIF/GPS stripping**, orientation applied before stripping, opt-out honoured
- Scanner behaviour including ClamAV fail-closed
- HEIF detection, MP4 brand rejection, HEIC→JPEG normalisation

**Found and fixed during the step**
The CLI demo showed a 4 KB executable renamed `.jpg` being rejected as
`FILE_TOO_SMALL` — technically true but misleading, since it would send the
employee off to retake a photo that could never work. Type detection now runs
before the lower size bound, so the real problem is named. Regression test added.

**Verified**
- `ruff check` clean · `ruff format --check` clean · 253/253 tests
- `avs ingest` exercised against a valid EXIF/GPS JPEG (accepted, rotated,
  stripped) and a disguised PE binary (refused by type)

**Notes for later steps**
- `imaging/` (Step 4) consumes `ValidatedImage.data` — always JPEG, PNG or WebP,
  upright, metadata-free
- Ingest limits are currently constructor arguments; Step 8 wires them to
  per-tenant policy
- `pillow`/`pillow-heif` moved into an `ingest` extra: install with
  `pip install -e ".[dev,crypto,ingest]"`

---

### Step 4 — Image Preprocessing · ✅ 13 Aug 2026

**⚠ Contract change: 1.0.0 → 1.1.0**
`VariantGenerator.generate` now returns `Iterable[ImageVariant]` instead of `list`.
**Widening, not breaking** — a list still satisfies the annotation. Motivation: ~23
encoded variants of a 12 MP photo is several hundred megabytes, and the Step 5
cascade stops at the first success, so materialising them all is waste. Consumers
reviewed: `qr/` (Step 5, not yet built) — no existing code affected. Recorded in
the CONTRACTS.md changelog.

**Built**

`imaging/ops.py` — 15 pure operations on numpy arrays
- Contrast: CLAHE · illumination: flat-field correction · glare: blob-gated inpainting
- Sharpness: unsharp mask · resolution: cubic upscale · noise: bilateral (edge-preserving)
- Binarisation: Otsu and adaptive · geometry: 90° rotation, document quad detection,
  perspective warp
- Measurement: `estimate_blur`, `estimate_glare_fraction` (crude, superseded by Step 14)
- `encode_png` — lossless, never JPEG

`imaging/strategy.py` — ★ the Step 14 seam
- `Problem` enum: the 8 things that stop a dense QR decoding in a real photo
- `Strategy` dataclass: name, operations, tier, **`addresses`** — the problems it fixes
- `STRATEGIES`: 23 recipes across 5 tiers
- `select_strategies(quality)` — full matrix when `quality is None`; narrowed to
  tier 0 + strategies addressing detected problems when the model is present
- `problems_from_quality()` — the entire integration surface for Step 14

`imaging/generator.py` — `PreprocessingVariantGenerator`
- Lazy, cheapest-tier-first yielding
- **Region seam (Step 15)**: crops to a located QR with quiet-zone padding
- **Quality seam (Step 14)**: narrows the strategy set
- Warp computed once and reused across all tier-3 strategies
- Failing strategies skipped, not fatal

CLI
- `avs preprocess <image> [--out DIR] [--max-tier N] [--limit N] [--no-warp]` —
  per-strategy cost table; `--out` writes each variant as a PNG so you can see
  exactly what the decoder will be handed

**Tests: 322 passing** (up from 253) — 69 new
- Every operation: dimension preservation, dtype, idempotency, measured effect
  (flat-field genuinely flattens a gradient; CLAHE genuinely raises contrast)
- Lossless PNG round-trip
- Document detection finds real quads, declines on noise
- Strategy table: unique names, tier-0 cheapness, full `Problem` coverage
- Selection: full matrix without a model, narrowed with one, **low `decodability`
  falls back to everything** rather than guessing wrong
- Generation: laziness, tier ordering, `original` first, PNG output, limits
- Both seams independently and together

**Two real bugs the tests caught**
1. `suppress_glare` inpainted any image with >0.1% bright pixels — which includes
   every photo of a white card. Now morphologically opens the mask first, so only
   contiguous blown-out blobs count as glare.
2. `find_document_quad` traced the *image border* on busy input and reported it as
   a perfect rectangle. Now rejects quads covering >95% of the frame.

Also fixed: `select_strategies` sorted alphabetically, putting `gray` before
`original`. Ordering is now tier + declaration order, so an already-good capture
decodes on variant 1.

**Measured** (1600×1200 noise image, tiers 0–2, sandbox CPU)
- Variant 1 (`original`): ~320 ms · full 16-variant run: ~2.3 s
- Confirms the laziness decision: a good capture pays ~1/7 of the worst case

**Notes for later steps**
- `qr/` (Step 5) consumes the `Iterator[ImageVariant]` and must **stop at the
  first successful decode** — that is what makes tier ordering pay off
- Step 5's benchmark should record decode rate *and* mean variant index, since
  the latter is the latency driver
- `ai/quality/` (Step 14) only needs to emit `QualityScores`; `problems_from_quality`
  already translates it into strategy selection

---

### Step 5 — QR Decoder Cascade · ✅ 13 Aug 2026

**⚠ Contract change: 1.1.0 → 1.2.0** (both backwards compatible)
(a) `QrDecoder.decode` accepts `Iterable[ImageVariant]`, matching the 1.1.0 widening
so the cascade consumes Step 4's lazy stream. (b) `DecodeResult` gains
`foreign_qr_found: bool = False` — additive with a default.

**Built**

`qr/decoders.py` — four backends behind one Protocol
- `ZxingDecoder` (first — strongest on dense symbols), `WeChatDecoder`,
  `ZbarDecoder`, `OpenCvDecoder` (last — always present)
- Each reports its own availability; unavailable ones are skipped, never fatal
- No backend ever raises: garbage in, empty list out

`qr/cascade.py` — `QrDecoderCascade`
- Variant-major loop, stopping at the first accepted payload
- `classify_payload()` → `SECURE_QR` / `LEGACY_XML` / `FOREIGN`
- Foreign QRs are flagged and skipped, not accepted
- `max_variants` and `time_budget_seconds` bounds

`tests/fixtures/qr_images.py`
- Renders a real Secure-QR-sized payload (~1,700 digits → ~109 modules) onto a
  card-shaped image with text-like blocks
- 8 degradation families: blur, noise, contrast, glare, perspective, resolution,
  compression, combined

`scripts/benchmark_decode.py`
- `--synthetic` — the degradation sweep, runnable today
- corpus mode — real photos via `AVS_CORPUS_DIR`
- Reports decode rate, **mean variant index**, time-to-success vs time-to-failure,
  decoder and strategy distribution. No personal data in any output.

CLI
- `avs decode <image>` — full pipeline; payload withheld unless `--show-payload`
- `avs decoders` — backend availability
- `avs doctor` now shows backend availability too

**Tests: 364 passing** (up from 322) — 42 new

**★ BASELINE MEASURED — synthetic sweep, 26 cases**

```
decode rate         80.8%  (21/26)
mean variant index  1.3    (median 1, max 7)
decoded on v1       20/21
mean time success   251 ms
mean time failure   4274 ms

by family:  clean 100% · compression 100% · contrast 100% · noise 100%
            perspective 100% · blur 67% · glare 67% · combined 75%
            resolution 33%
```

**Three findings worth recording**

1. **Tier ordering is validated.** 20 of 21 successes decoded on variant 1 —
   `original`, before any preprocessing. Step 4's cheapest-first design works.

2. **Preprocessing contributed exactly one recovery** in this sweep
   (`gray+sharpen` on a blurred card). Honest reading: on *synthetic* degradation
   most of the value is in the decoder, not the 23-strategy matrix. Real captures
   with genuine lighting and perspective should shift this — but that is a
   prediction, not a measurement, until the real corpus runs.

3. **Failure costs 17x more than success** (4.3 s vs 251 ms). An undecodable image
   burns the entire matrix. This is the case for the time budget now, and for the
   Step 14 quality model later — predicting "this will not decode" before spending
   4 seconds proving it.

Two `resolution` failures were rejected at *ingest* (`DIMENSIONS_INVALID`,
`FILE_TOO_SMALL`), not by the decoder — correct behaviour, since an image that
small cannot hold a readable Secure QR.

**Notes for later steps**
- ⚠ **Step 6 scope extended** (contract 1.3.0 §11): the verdict engine now assembles
  a document from TWO images rather than judging one. See D51-D56.
- Step 6 maps `DecodeResult` → verdict: `success` → parse; `foreign_qr_found` →
  "this is not an Aadhaar card"; otherwise `UNREADABLE`
- Step 7's worker should set `time_budget_seconds` from tenant policy
- Re-run `benchmark_decode.py --synthetic` after Steps 15, 16 and 19 — same sweep,
  directly comparable numbers
- The real-corpus baseline is still outstanding and is the number that matters

---

### Step 6 — Verdict Engine, Privacy & Document Assembly · ✅ 13 Aug 2026 · 🏁 MILESTONE A

**Contract 1.3.0 completed** — §11 Two-Sided Capture implemented. Added
`CardSide`, `CardSideOutcome`, `VerificationResult.sides`, and a 12th check name
`side_agreement` (all additive).

**Built**

`rules/` — the deterministic verdict engine
- Decision table mapping evidence to the 9 frozen verdicts. No scores, no thresholds.
- **Sees only `CheckOutcome` + `SignatureProof`** — the AI boundary made structural
- Advisory failures route to review in severity order: duplicate → side agreement →
  OCR → name → DOB
- `Strictness` affects **routing only**; no setting enables auto-rejection
- `messages.py` — one message per verdict, none of which accuse the employee

`privacy/` — `DataMinimisingFilter`
- Runs once, at the boundary, over the finished result
- `reference_id` → salted HMAC-SHA256, then destroyed
- Address and photo dropped unless explicitly requested
- Refuses the placeholder secret at construction

`pipeline.py` — `DocumentVerifier` (new module)
- Assembles TWO card faces into ONE verdict
- Finds the Secure QR on **either** side
- `side_agreement` catches two different payloads on one document
- Document-level time budget, shared fairly across sides
- Never raises

CLI — `avs verify <front> <back>`, showing per-side outcomes, every check, the
verdict, and the exact message the employee sees.

**Tests: 465 passing** (up from 364) — 101 new

**Three real problems found and fixed during the step**

1. **`ERROR` was being used for rejected uploads.** `ERROR` tells the employee to
   wait; a bad file is a retry. Now `UNREADABLE`, and `file_validation` is checked
   before `qr_decoded` so the message names the real problem.

2. **No time bound at all.** Two unreadable sides cost ~9 s of CPU proving a
   negative — unbounded, one bad photo holds a worker while others queue.
   Added a document-level budget, default 12 s.

3. **★ A bad front photo starved a good back.** First-come-first-served budgeting
   gave the front 7.8 s of a 12 s budget, leaving the back almost nothing. Since
   the QR is usually on the side people upload *second*, that was the common case.
   Each side now gets `remaining / sides_left`, and unused time rolls over.

**Verified end to end from image bytes**
- Genuine card (QR on back) → `VERIFIED`
- Genuine card (QR on front) → `VERIFIED` — never assume "QR = back"
- One field edited → `TAMPERED`
- Signed by a different key → `TAMPERED`
- Empty trust store → `ERROR`, never `TAMPERED`
- Two different Secure QRs → `TEXT_MISMATCH`, human review
- One side unreadable, other verifies → `VERIFIED` with an explaining message

**Notes for later steps**
- Step 7 wraps `DocumentVerifier.verify()`; `is_ready` feeds the readiness probe
- `time_budget_seconds` should come from per-tenant policy in Step 8
- Steps 17/18 add `ocr_cross_check`, `profile_name_match`, `profile_dob_match`,
  `duplicate_check` — the engine already routes all four
- `expected` is accepted by `verify()` and unused until Step 18

---

<!-- Append each completed step below, newest last. -->

## Step 7 — REST API & Async Worker  ·  14 August 2026

**Milestone B begins.** Steps 0–6 produced a verifier callable from Python and a
CLI. Step 7 makes it reachable over HTTP, which is the only form the HRM can use.

**Built**

| Module | Contents |
|---|---|
| `api/app.py` | `create_app()`, `AppState`, 4 verify routes, 3 ops routes |
| `api/models.py` | `VerifyUrlRequest`, `JobAccepted`, `JobStatusResponse`, `ReadyResponse` |
| `api/callbacks.py` | `CallbackDispatcher` — HMAC over `timestamp.nonce.body`, 3 attempts with backoff |
| `worker/queue.py` | `JobQueue` Protocol, `InProcessJobQueue`, `Job`, `JobStatus`, `QueueFull` |
| `storage/fetcher.py` | `SafeUrlFetcher`, `is_safe_url() -> UrlCheck`, `FetchError` |
| `cli.py` | `avs serve` |

66 new tests (`test_api.py` 21, `test_worker.py` 20, `test_storage.py` 25).
**523 passing, lint clean.**

**Four real defects found and fixed during the step**

1. **★ SSRF refusals returned `202`.** The safety check ran in the worker, so a
   caller had to poll to discover that a URL had been *refused on security
   grounds* — and every probe consumed a queue slot. Now checked synchronously
   before the job is created: `400`, no job, nothing queued.

2. **★ `already_queued` was true on the first submit.** It was inferred from job
   status, but with a free worker the job flips to `RUNNING` before `submit`
   returns. Every submission looked like a duplicate. `submit()` now returns
   `(job, created)` and states the fact rather than guessing at it.

3. **DNS failure was reported as a permanent refusal.** A resolver blip would
   have returned `400 retryable:false` for perfectly legitimate URLs. `UrlCheck`
   now separates `blocked` (forbidden forever → `400`) from a failed check
   (transient → `503`, retry).

4. **Counters raced.** `d[k] = d.get(k,0)+1` from two worker threads loses
   counts. Now under a lock, with `counter_snapshot()` for reads.

**Verified end to end over HTTP**
- Genuine document → `202`, poll → `VERIFIED`
- QR on the front instead of the back → `VERIFIED`
- Same `job_id` twice → one verification, `already_queued: true` on the retry
- 10 threads submitting one `job_id` simultaneously → work ran exactly once
- `169.254.169.254`, `127.0.0.1:6379`, `10.0.0.5`, `192.168.1.1` → `400`, no job
- `file:///etc/passwd` → rejected at validation
- Hostname resolving to `127.0.0.1` → refused (the check is on the address)
- Empty trust store → `/health` 200, `/ready` **503**, verdict `ERROR` not `VERIFIED`
- No 12-digit number anywhere in an API response

**Deliberately NOT done in this step**
- **No authentication.** Anything that can reach the port can submit a document.
  Step 9. Bind to localhost behind a reverse proxy until then.
- **No rate limiting** beyond queue capacity. Step 9.
- **No durable queue.** In-process loses jobs on restart — fine for one
  instance, wrong for a cluster. Step 8.
- **No object-store writes.** `storage/` only *fetches*. Step 8.

**Two follow-ups after Dheeraj first ran it (14 Aug)**

5. **`python-multipart` was missing and failed with a 60-line traceback.**
   FastAPI raises at *route-registration* time, so the whole app fails to build.
   `avs serve` now preflights it and `uvicorn`, and prints the install command.
   Also: rich was swallowing `[service]` as a markup tag, so the message read
   `pip install -e "."` — escaped now.

6. **★ The usage commands I gave were bash curl, run in PowerShell.** There
   `curl` is an alias for `Invoke-WebRequest`, which rejects `-X` and `-F`.
   Added `scripts/smoke_api.py` — httpx, cross-platform, asserts every expected
   outcome including the SSRF refusals. It sets `trust_env=False` so a corporate
   proxy cannot sit between the test and 127.0.0.1.

---

## Step 7.5 — Real-world decode rate  ·  14 August 2026

**Trigger.** Dheeraj collected 22 real photos across 2 phones. `corpus_report.py`
measured a **22.7% decode rate**, with every success coming from the untouched
image at variant index 1 — all 23 preprocessing strategies rescued nothing.

**Root cause (measured, after three wrong hypotheses).**

| | generate | zxing decode | 23 strategies |
|---|---|---|---|
| 12MP, QR present | 0.49s | 0.54s | 23.8s |
| **12MP, no readable QR** | **0.82s** | **1.81s** | **50.0s** |
| 1800px, no readable QR | 0.17s | 0.31s | 8.9s |

zxing is slowest precisely when it fails, because it searches the entire frame
before giving up. `working_max_edge` was 4000 and phone photos are 4032px, so
**nothing was ever downscaled**. At 2.63s per variant a 12s budget bought 4-6 of
23 strategies. This reproduces the corpus numbers exactly: 12MP failures showed
4-6 variants in 16-18s, 2.3MP images showed 18-19 in 8s.

**Fix.** Locate the QR on a cheap 1400px scout, crop to it with 60% context,
scale so the QR lands at 520px (~5.4 px/module). Fall back to a hard 1500px cap
when nothing is located, because the localiser is more sensitive than the decoder
and "nothing found" means "fail fast".

| | before | after |
|---|---|---|
| 12MP, QR present | 23.8s | **0.3s** |
| 12MP, no readable QR | 50.0s | **5.7s** |
| End-to-end two-sided document | 32.7s | **7.5s** |

**Three wrong hypotheses, recorded so they are not repeated**
1. *Resolution* — wrong. Every QR measured above 3.27 px/module.
2. *Front-face non-Secure QR* — wrong. `WRONG_QR_ON_THIS_FACE` came back 0.
3. *Trusting my own localiser* — wrong. Its boxes were unvalidated on failing
   images, and 10 of 22 changed once the geometry check was added.

**Corpus re-run after the fix.** Variants tried per image went 4-6 -> **19**;
time 16-18s -> **3-8s**; and preprocessing rescued 2 images for the first time
(`gray+upscale`, `gray+upscale+clahe+sharpen+adaptive`) where previously every
success came from `original`. So the strategy set now genuinely runs.

The headline rate did NOT move (22.7%), and the re-run exposed two further
problems: a **regression** (`phone-b-angled` 1/6 -> 0/6, a mislocated crop
discarding a decodable QR — fixed by D85) and the fact that **3 of the 5
"decodes" never parsed**, making the usable rate 2/22 = 9% (D86).

**RESOLVED.** The 3 payloads that decoded but would not parse were killed by a
UTF-8 assumption in `_split_fields` (D91). Container diagnostics proved the
payloads were healthy — gzip magic `1f8b`, decompressed cleanly, 46 delimiters
present, 90% printable — which is what made the parser the only suspect left.

**FINAL RESULT — the parsing pipeline is closed out.**

| | start of Step 7.5 | end |
|---|---|---|
| real cards VERIFIED | 0 | **5** |
| decoded payloads that parse | 2/5 | **5/5** |
| `PAYLOAD_MALFORMED` | 3 | **0** |
| remaining failures | — | `QR_NOT_FOUND` x17, a CAPTURE problem |

All 5 verified **via lapsed certificates** — without D89 every one would have
returned TAMPERED. `FIELD_MAPS` confirmed against real cards with zero shape
mismatches, and independently against UIDAI's published sample payload.

**Everything the system can READ, it now correctly VERIFIES.** The remaining
22.7% decode rate is capture quality, not correctness — it belongs to Steps 11,
14 and 16 (on-device capture guidance), not to the deterministic core. The synthetic
QRs are too robust to reproduce the failures, so only a re-run on the real
corpus can tell us. `avs_decode_rate` must be a tracked metric from Step 9.

---

**Notes for later steps**
- Step 8 replaces `InProcessJobQueue` by implementing the same `JobQueue`
  Protocol; nothing above it changes
- `allow_private_urls` must stay false in production — it reopens the SSRF hole
- `AVS_HASH_SECRET` must be stable across deployments or reference hashes change
- Alert on `avs_certificate_days_to_expiry < 90`; at 0 the service stops
  verifying anything
- Step 10's Spring client codes against CONTRACTS.md §8, now matching reality

---

## Step 12 — ML Foundation  ·  17 August 2026

**Milestone D begins.** Steps 13–19 each add a model. Without shared machinery
each would invent its own loading, versioning and failure behaviour, and the
pipeline would acquire five subtly different ways to break. Step 12 ships no
model at all — it builds the thing that makes the next four safe to add.

### What was built

| File | |
|---|---|
| `src/avs/ai/modelmgr/registry.py` | `ModelSpec`, `ModelRegistry`, `load_registry()`, `RegistryError` |
| `src/avs/ai/modelmgr/runtime.py` | `ModelRunner`, `InferenceSession`, `InferenceOutcome` |
| `src/avs/cli.py` | `avs models status`, `avs models pin` |
| `tests/unit/test_ai_foundation.py` | 22 tests |
| `tests/unit/test_ai_boundary.py` | +4 tests — the reverse boundary |

### Found by running it

`avs models pin` on a directory holding a 0-byte file pinned it happily,
printing `e3b0c442…` — the SHA-256 of zero bytes. A digest over garbage is
still a *valid* digest, so `models status` would then have shown `pinned ✓` and
an operator would reasonably have concluded the model was verified.

Pinning answers *"is this the file we chose?"*. It cannot answer *"is this a
model?"* — so the CLI now refuses empty files outright and warns below 1 KiB.
Three regression tests cover it (D126).

### The one rule

**A model must never be able to fail a verification.** Six failure modes, each
exercised by a test, each ending in "carry on deterministically":

| Failure | Behaviour |
|---|---|
| No model declared | Empty registry, exit 0. The *normal* state |
| `onnxruntime` absent | Logged, `None` returned |
| Digest mismatch | Refused loudly, never loaded |
| Model throws | `usable=False`, reason recorded |
| Model hangs | Abandoned at `max_inference_ms` (default 500ms) |
| Model returns nothing | `usable=False` |

`ModelRunner.with_fallback()` is the shape every AI module will use, so no
module can forget its fallback — that omission is exactly how "optional"
degrades into "required in practice".

### Why models are pinned like certificates

An ONNX graph is a program. onnxruntime interprets it, it can carry custom
operators, and a maliciously crafted one is an attack on the loading process.
Dropping a file into `models/` is closer to dropping a `.so` into the library
path than to adding config — so `models.json` records a SHA-256 per file and a
mismatch is refused before onnxruntime sees it.

⚠ This is defence in depth, **not** the thing standing between an attacker and
an approval. If every model here were replaced with a hostile one, the worst
outcome is bad preprocessing advice and a re-upload prompt. Forging an approval
still requires UIDAI's private key.

### What was found — a four-step version drift

`test_contract_version_is_pinned()` asserted `CONTRACT_VERSION == "1.3.0"` and
passed on every run while CONTRACTS.md advanced to 1.7.0. `avs version` had been
reporting a contract version that had not existed for weeks, and nothing failed.

The shape is identical to the Step 7.5 `"V2"` bug: **a test that pins a literal
proves only that the literal has not changed.** The test now parses the version
out of CONTRACTS.md, so the constant and the document cannot drift apart again.
Both were bumped to 1.8.0 (D125).

### Verification

- 631 tests pass (was 601 — Step 12 adds 30), ruff clean, 116 files formatted
- `avs models status` proven against all three states: empty registry (exit 0),
  correctly pinned (exit 0), swapped file (exit 1, digest mismatch named)
- The reverse AI boundary is asserted by AST inspection, not by convention

---

## Step 13 — Document Type Classifier  ·  17 August 2026

The first AI component whose output travels alongside a verdict. Everything
before it was upstream of the decision or outside the service entirely, so this
is where the AI boundary had to stop being module layout and start being runtime
behaviour.

### The problem it solves

Someone uploads a payslip, a PAN card, or an accidental photo of the floor. The
QR is not found, so they are told:

> "We could not read the QR code. Please photograph both sides of your Aadhaar
> card in good light, holding the card flat and filling the frame."

They retake it in better light. It fails identically. Nothing in that message
could ever have told them why — it names a cause that is not the cause.

### What was built

| File | |
|---|---|
| `src/avs/ai/classify/features.py` | `DocumentFeatures`, `extract_features()` — pure measurement |
| `src/avs/ai/classify/heuristic.py` | `HeuristicClassifier` — works today, no model |
| `src/avs/ai/classify/onnx.py` | `OnnxDocumentClassifier` — the seam for real weights |
| `src/avs/ai/classify/__init__.py` | `build_classifier()` — prefers model, falls back |
| `src/avs/pipeline.py` | optional `classifier=`, message refinement only |
| `src/avs/cli.py` | `avs classify` |
| `scripts/collect_classifier_features.py` | corpus measurement, numbers only |
| `tests/unit/test_classify.py` | 22 tests |
| `tests/unit/test_classify_never_changes_verdict.py` | 20 tests |

### ★ The measurement that set the design

The obvious heuristic is "documents are dense with edges — text, rules, borders
— so high edge density means a document". Measured::

    card with QR       0.052
    card without QR    0.042
    handwritten page   0.035
    ─────────────────────────
    random noise       0.104   ← 2x the card
    brick wall         0.104   ← 2x the card

**A brick wall is twice as "document-like" as an Aadhaar card on the obvious
feature.** High edge density means nothing; any textured scene satisfies it.

So only the low end is asserted — near-zero edges, no document quad and no QR
means no document — and everything else answers UNKNOWN. That is a much smaller
claim than "document classifier", and it is the claim the measurement supports
(D127).

### Why it cannot change a verdict

Three independent reasons, any one sufficient:

1. It runs *after* `rules.decide()` has returned. The verdict already exists.
2. It writes only `user_message` and `ai_trace`. It never receives `verdict`,
   `proof`, `checks` or `error`.
3. It returns early on anything but UNREADABLE — **a VERIFIED document is never
   classified at all**, so no output exists that would have to be ignored.

`test_classify_never_changes_verdict.py` feeds the pipeline a classifier that
returns every `DocType` at confidence 1.0 and asserts verdict, proof, error and
the full check list are identical to the no-classifier run. A component that
lies about everything with total certainty still cannot move the outcome.

### Found while building

Wiring refinement revealed the pipeline would have **ingested every image
twice** — once to decode, once to classify. Worse, the second ingest could fail
independently, losing the refinement for no reason. `_SideResult` now carries
the already-ingested `ValidatedImage` (in memory, for the life of one call;
`test_statelessness.py` still fails the build if bytes reach disk).

### ★★ CORRECTED BY REAL DATA, SAME DAY

Ran the collector against the 22-image corpus. It contradicted the design::

    phone-a-dim   4 images   0.0000 / 0.0019 / 0.0096   ← REAL CARDS

Three genuine Aadhaar cards sat **at or below** `EDGE_DENSITY_FLOOR = 0.005`.
Underexposure destroys edge structure, so a dim card and a blank wall are
identical on that feature — the classes overlap completely at the low end, which
is the reverse of what the generated data showed. They survived only because the
QR/quad check happened to fire first.

**And my own safety check hid it.** The script filtered documents with
`"aadhaar" in label`; the real folders are `phone-a-dim`, `scanner`, so it
matched zero rows, compared against an empty set, and printed ✓.

Both fixed (D132, D133): `NOT_A_DOCUMENT` now requires adequate exposure, and
the collector treats everything as a document unless a folder says otherwise.

### Verification

- **680 tests pass** (was 631 — Step 13 adds 49), ruff clean, 122 files formatted
- `avs classify` proven on generated inputs
- Contract 1.9.0, code and document consistent (the D125 check holds)

### ★★★ THE HEURISTIC WAS MEASURED AND RETIRED — same day

19 real wrong-upload images were added to the corpus. The heuristic caught
**0 of them**::

                   edge density        brightness
    DOCUMENTS   0.0000 - 0.1232      41.0 - 174.6
    NEGATIVES   0.0031 - 0.0886       3.7 - 235.2

The negative range is *entirely inside* the document range on edge density —
100% overlap. No threshold separates the classes, so this is not a tuning
problem. A screenshot of text IS a document image; distinguishing an Aadhaar
from it needs CONTENT understanding, which shape statistics cannot provide.

`build_classifier()` now defaults to `allow_heuristic=False`, so the heuristic
no longer runs for employees. It is kept, not deleted: it is the reference
implementation of the Protocol that Step 14 will follow, the collector scores it
so the decision can be revisited, and its tests record what was tried (D135).

**What Step 13 therefore delivered** is not a working classifier. It is the
seam for one — feature extraction, the ONNX adapter, pipeline wiring, and the
runtime proof that no classifier output can move a verdict — plus the
measurement infrastructure that proved the interim version does not work.
Learning that from real data now is worth more than shipping something that
quietly did nothing.
