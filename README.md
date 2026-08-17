# AVS — Aadhaar Verification Service

Standalone verification service for **M-One HRM**. Determines whether an uploaded
Aadhaar card image is genuine, by verifying the **UIDAI RSA-2048 signature** embedded
in its Secure QR code.

---

## The governing principle

> **AI makes the system smart. Cryptography makes it correct.**

```
   AI ──────────► INPUT SIDE
                  classify · quality · localize · restore
                  purpose: make bad images decodable

   ✕  ──────────  THE VERDICT
                  crypto.verify() — RSA-2048 / SHA-256
                  no AI · no heuristics · no thresholds · no scores

   AI ──────────► HUMAN-ASSIST SIDE
                  ocr · namematch · assist · support · anomaly
                  purpose: make review fast and fair
```

The signature check sits **downstream** of everything AI touches. If a model
degrades or mispredicts, the worst outcome is a re-upload prompt — **never a false
approval**. Forging an approval would require UIDAI's private key, which no amount
of image enhancement can produce.

| Property | Guarantee |
|---|---|
| Tampered document detected | **100%** — any byte changed breaks the signature |
| Genuine document falsely rejected as fake | **0%** |
| AI failure causing a false approval | **Impossible** |
| Confidence score in the verdict | **None** — binary, not probabilistic |

---

## Legal position

| | |
|---|---|
| UIDAI licence (AUA/KUA) | **Not required** |
| OVSE registration | **Not required** for QR verification of an uploaded copy |
| Third-party vendor | **None** |
| Per-verification cost | **Zero** |
| Network call to UIDAI at verification time | **None** |

All models run locally inside the container. No image and no demographic data ever
leaves your infrastructure — the service runs with outbound internet firewalled shut.

---

## Quick start

Requires **Python 3.12 or newer**.

**Windows (PowerShell)**

```powershell
cd aadhaar-verification-service
python -m venv .venv
.venv\Scripts\Activate.ps1        # if blocked: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
pip install -e ".[dev,crypto]"

avs selftest
```

**macOS / Linux**

```bash
cd aadhaar-verification-service
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,crypto]"

avs selftest
```

### Commands

```
avs selftest     # prove the crypto core works — no real Aadhaar needed
avs version      # service and contract versions
avs contracts    # print the frozen verdict/check surface
avs doctor       # environment check and build progress
avs verify-qr --file payload.txt --show-fields

pytest -q        # 149 tests
ruff check src tests
```

> ### ⚠ `avs: command not found` / `'avs' is not recognized`
>
> This means you installed **outside a virtualenv**. pip put `avs.exe` in a user
> scripts directory that isn't on your PATH — it warns about this, but the notice
> is easy to miss in the install output.
>
> **Run it directly instead:**
>
> ```
> python -m avs.cli selftest
> ```
>
> **Or fix it properly** by using a virtualenv as shown above. Inside an activated
> venv, `avs` is on PATH automatically — and later steps add OpenCV, ONNX Runtime
> and PaddleOCR, which you really don't want in your system Python.

---

## Documentation

| File | Purpose |
|---|---|
| **`CONTRACTS.md`** | ⛔ **Frozen interfaces.** Read before changing anything. |
| **`PROJECT_STATE.md`** | 📍 **Living memory.** Read at the start of every step, update at the end. |
| `certs/README.md` | Trust store rules and certificate rotation |
| `tests/fixtures/README.md` | Corpus handling and the privacy rule |
| `benchmarks/README.md` | Decode-rate tracking across AI steps |

---

## Repository layout

```
src/avs/
├── contracts/      ✅ frozen enums, models, Protocols — the architectural seams
├── config/         ✅ settings
├── logging/        ✅ structlog + mandatory PII redaction
├── cli.py          ✅ avs command
│
├── parser/         Step 1   Secure QR payload parsing
├── crypto/         Step 1   ★ signature verification — THE VERDICT
├── truststore/     Step 2   UIDAI certificates, rotation-tolerant
├── ingest/         Step 3   file validation — first security boundary
├── imaging/        Step 4   deterministic preprocessing
├── qr/             Step 5   decoder cascade
├── rules/          Step 6   deterministic verdict engine
├── privacy/        Step 6   masking, hashing, redaction
├── api/            Step 7   FastAPI
├── worker/         Step 7   async queue
├── health/         Step 7   probes
├── storage/        Step 8   object storage
├── security/       Step 8   mTLS, HMAC
├── audit/          Step 9   hash-chained trail
├── observability/  Step 9   metrics, traces
├── ocr/            Step 17  text cross-check
├── matching/       Step 18  identity binding
└── ai/
    ├── modelmgr/   Step 12  registry, versioning, graceful fallback
    ├── classify/   Step 13  document type
    ├── quality/    Step 14  capture quality ★ highest ROI
    ├── localize/   Step 15  QR region detection
    ├── namematch/  Step 18  Indian name matching
    ├── restore/    Step 19  image restoration (retry path)
    ├── assist/     Step 20  HR reviewer copilot
    ├── support/    Step 21  multilingual guidance
    └── anomaly/    Step 25  fraud pattern detection
```

Every stub records its own contract — step, provides, consumes — in its docstring.

---

## ⛔ Privacy rules for this repository

**Never commit any of the following:**

- Real Aadhaar images
- Real QR payload strings
- Real Aadhaar numbers — in code, tests, comments, or commit messages

The corpus lives **only on your machine**, outside this repository:

```bash
export AVS_CORPUS_DIR=/your/path/aadhaar-corpus
pytest -m corpus
```

Corpus-dependent tests skip automatically when it is absent, so CI stays green
without ever seeing the data. `.gitignore` blocks corpus paths and CI fails the
build if Aadhaar data is detected in the tree.

---

## The two rules the code enforces

**Rule 1 — `VERIFIED` is the only auto-approval, and it requires a valid signature.**
Asserted by `tests/unit/test_contracts.py::test_rule_1_only_verified_auto_approves`
and double-checked in `VerificationResult.is_auto_approve`.

**Rule 2 — Nothing is ever auto-rejected.** Every non-verified outcome routes to a
re-upload prompt or a human reviewer. Asserted by
`test_rule_2_nothing_is_ever_auto_rejected`.

**Language rule** — the word *"fake"* must never appear in employee-facing text.
Use *"could not be verified."* A genuine card photographed badly is not a forgery.

---

## Build status

**Step 0 of 25 complete** — Foundation & Contract Freeze.
See `PROJECT_STATE.md` for the full registry and what's next.
