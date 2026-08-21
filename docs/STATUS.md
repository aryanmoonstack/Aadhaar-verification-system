# Aadhaar Verification System — Status

**20 August 2026 · Contract 2.0.0 · 13 of 26 steps complete**

A standalone service that decides whether an uploaded Aadhaar is genuine, by
verifying UIDAI's own cryptographic signature. Decoupled from M-One HRM: no
DigiLocker, no UIDAI API call, no dependency on any HRM feature.

---

## Where it stands

| | |
|---|---|
| **Working today** | Employee uploads an image or PDF → verified in 1–3 s → APPROVED / RETRY / REVIEW |
| **Proven on a real Aadhaar** | ✅ VERIFIED in 2.5 s against a real UIDAI certificate |
| **Python tests** | 802 |
| **TypeScript tests** | 80 |
| **Blocking work before pilot** | None. Deploy and measure |

---

## The one idea the system is built on

> **AI makes the system smart. Cryptography makes it correct.**

An Aadhaar's Secure QR carries the holder's data **and a 256-byte RSA signature
produced by UIDAI's private key**. AVS re-computes the hash and checks it against
UIDAI's public certificates.

Change one bit of that data and the signature fails. Forging it would require
UIDAI's private key. That is the whole verification — everything else is
plumbing to get a readable QR into it.

**Two rules are absolute:**

1. `VERIFIED` is the only auto-approval, and it requires a valid signature.
2. **Nothing is ever auto-rejected.** A genuine card photographed badly is
   indistinguishable from a forgery to any automated check — which is exactly
   why no automated check may call it one.

AI is used on the input side (is this a document? is it readable? where is the
code?) and the human-assist side. **AI never touches the verdict.**

---

## Architecture

```
  EMPLOYEE
     │  uploads image(s) or one PDF
     ▼
  HRM FRONTEND  (Next.js)
     │  browser pre-check ~50 ms — is the QR readable before we send it?
     ▼
  NEXT.JS ROUTE HANDLER  (server-side)
     │  holds AVS_SECRET · signs with HMAC-SHA256 · derives the PDF password
     ▼
  ══════════ HTTPS ══════════
     ▼
  AVS  (Python / FastAPI)              ← standalone, multi-tenant
     │
     ├─ 1  INGEST        magic bytes → malware scan → bomb guards → EXIF stripped
     │                   PDF? render pages at 300 DPI, then rejoin the image path
     ├─ 2  PREPROCESS    23 variants — deblur, contrast, perspective, upscale
     ├─ 3  DECODE        4 QR backends, tried in cost order until one reads
     ├─ 4  PARSE         digits → bytes → decompress → fields + signature
     ├─ 5  ⛔ VERIFY     RSA-2048 / SHA-256 against 5 pinned UIDAI certificates
     ├─ 6  RULES         one of exactly 9 verdicts. Deterministic
     └─ 7  PRIVACY       Aadhaar number never returned · address dropped by default
     │
     ▼  decision { status_code, status, message, verdict, signature_valid }
  NEXT.JS ROUTE
     │  APPROVED only → writes a row
     ▼
  HRM POSTGRES        CHECK (verdict <> 'VERIFIED' OR signature_valid = TRUE)
```

**Why the browser never calls AVS directly:** signing requires a secret, and
anything shipped to a browser is public. The Next.js *route handler* is
server-side Node — the frontend team owns the whole path, and no backend
service is involved.

---

## Built — Milestones A to D

### A · Deterministic Core (Steps 0–6) ✅

| Step | |
|---|---|
| 0 | Frozen contracts — 9 verdicts, 12 check names, error codes |
| 1 | RSA-2048/SHA-256 signature verification; Secure QR parser |
| 2 | Certificate trust store, SHA-256 pinned, expiry-aware |
| 3 | Ingest: magic bytes, malware scan, bomb guards, EXIF stripping |
| 3.5 | **PDF support** — render at 300 DPI, password handling |
| 4 | 23 preprocessing variants |
| 5 | 4-backend QR decoder cascade |
| 6 | Verdict engine + privacy filter |

⛔ **Certificate expiry does not decide authenticity.** UIDAI rotates its signing
key every few years, and an e-Aadhaar carries the signature it was issued with
forever. Requiring a currently-valid certificate would report the majority of
cards in circulation as `TAMPERED` — a false accusation of forgery against real
employees.

### B · Deployable Service (Steps 7–9) ✅

REST API with async workers · HMAC authentication with replay protection ·
multi-tenancy · hash-chained audit trail · Prometheus metrics.

### C · HRM Integration (Steps 10–11b) ✅

Next.js route handlers, upload component with browser pre-check, PDF support,
password derivation, the `decision` response shape, Postgres persistence.

⚠ Step 10 (Spring backend) was **built and then removed** once the frontend
began calling AVS directly. Its database schema survives — it carries the CHECK
constraints nothing else enforces.

### D · AI Vision Layer (Steps 12–14) ✅ · (15–16) pending

| Step | |
|---|---|
| 12 | Model registry + ONNX runtime, SHA-256 pinned |
| 13 | Document-type classifier |
| 14 | Capture-quality model — reorders preprocessing, never filters it |

---

## Pending — Milestones D to G

| Step | | Why it matters |
|---|---|---|
| 15 | QR Localiser | ⚠ **Evidence says skip.** Measured: the localiser already finds these codes, crops them at full resolution, and they still fail. Cropping recovers **0** decodes |
| 16 | On-Device Browser AI | Guidance before upload |
| 17 | OCR Cross-Check | Detects a **forged printed face** on a genuine card — the one real attack the signature cannot see |
| 18 | AI Name Matching + duplicate detection | `PROFILE_MISMATCH` and `DUPLICATE` are currently unreachable |
| 19 | Image Restoration | The indicated fix for unreadable photos, not Step 15 |
| 20 | HR Reviewer Copilot | Needs the review queue |
| 21 | Multilingual Assistant | |
| 22–25 | Hardening, UAT, Launch, Anomaly Detection | |

### What the pending steps mean in practice

Three of the nine verdicts cannot fire yet:

- `PROFILE_MISMATCH` — needs expected identity at submit time (Step 18)
- `TEXT_MISMATCH` — needs OCR (Step 17)
- `DUPLICATE` — needs the reference-hash index in use (Step 18)

The database columns for all three already exist, so adding them later is not a
migration against live identity data.

---

## What is measured, and what is not

**Measured:**

| | |
|---|---|
| Real Aadhaar PDF, end to end | ✅ VERIFIED, 2.5 s, real UIDAI certificate |
| Real Aadhaar photos over HTTP | ✅ VERIFIED, signature valid, audit chain intact |
| Photo decode rate, unguided corpus | **~30%** — the number that drives Steps 16/19 |
| Java↔Python↔TypeScript HMAC | ✅ identical across 6 shared vectors |
| Cropping to the located QR | recovers **0** decodes — rules Step 15 out |

**Not yet measured — the honest gaps:**

| | |
|---|---|
| PDF decode rate | 1 verified, 1 wrong password, 1 genuinely pre-2018. Too few to quote a rate |
| `BarcodeDetector` on real hardware | Never executed on a phone. The whole browser pre-check rests on it |
| Production decode rate | The number that decides whether Steps 16–19 are needed at all |

---

## Risks

| Risk | Status |
|---|---|
| Photo decode rate ~30% | ⚠ Open. PDFs should be far better; steering employees to PDF may remove the problem rather than solving it |
| A forged printed face on a genuine card | ⚠ Open until Step 17. Mitigated today by trusting **only** the signed QR data, never the printed text |
| Someone uploads another person's genuine card | ⚠ Open. Needs face matching; not scheduled |
| Certificate expiry breaking verification | ✅ Closed by design |
| Trust-store tampering | ✅ Closed by SHA-256 pinning — requires `FINGERPRINTS.txt` committed |
| Aadhaar number leaking into logs or DB | ✅ Closed — never returned, salted-HMAC reference only, DB CHECK enforces 4 digits |

---

## Immediate next steps

1. **Pin the certificates** and commit `certs/FINGERPRINTS.txt`
2. **Deploy AVS** with `--budget 5`, auth on, two secrets generated at deploy time
3. **Frontend integration** — in progress
4. **Pilot**, watching `avs_decode_rate`
5. **Then decide Steps 15–19** from the production number, not from prediction

⚠ Step 5 is deliberate. Step 15 was queued as the fix for the decode rate until
measurement showed the localiser was never the bottleneck. The same discipline
applies to the rest of the AI roadmap: build what the numbers ask for.
