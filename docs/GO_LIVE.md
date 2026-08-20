# Go-live checklist

Run in this order when the deployment is ready. Roughly 20 minutes.

---

## 1. Pin the certificates ⏱ 10 seconds

```powershell
python -m avs.cli certs pin --dir certs
```

⛔ **Do this before anything else.** Until the trust store is pinned, anyone who
can write to `certs/` can add a certificate and mint approvals for forged cards.
Commit `certs/FINGERPRINTS.txt` — that file existing is what makes tampering
detectable.

---

## 2. Check the deployment ⏱ 5 seconds

```powershell
python scripts\preflight.py --url <the URL your backend dev gives you>
```

Sends no images, reads no cards. Safe against production.

**Do not proceed while it reports blocking problems.** The four it catches are
each near-invisible at upload time:

| Fault | Symptom you'd chase instead |
|---|---|
| `certs/` empty | every card returns ERROR, genuine ones included |
| trust store unpinned | silent — approvals can be minted |
| secret mismatch | 401, looks like a network problem |
| `AVS_HASH_SECRET` unset | silent — duplicate detection never matches |

---

## 3. Set the time budget ⏱ deploy flag

```
--budget 5
```

Measured: a card that decodes takes **0.35 s** and always succeeds on the first
variant. A card that cannot decode scales directly with the budget — 1.3 s at a
1 s budget, 7.6 s at 12 s.

So the budget only ever costs FAILURES time. At 12 s an employee with one
unreadable side waits 12 seconds; at 5 s they wait 5, and no successful decode
is affected.

⚠ Watch `avs_decode_rate` after changing it. Every success in the corpus decoded
on attempt 1, but that is 8 successes. If the rate drops, raise it back.

---

## 4. Confirm the frontend wired the PRE-CHECK, not just the file input

`AadhaarUpload.tsx` is the right component — `AadhaarCapture.tsx` is the live
camera and does not fit an upload flow.

The value is `precheck()` running on the chosen file **before** upload. Without
it the employee uploads a 12 MP file over mobile data, waits, and is rejected.
With it they know in ~50 ms.

⛔ Upload must never be BLOCKED by the pre-check. A photo the browser cannot
read may still decode on the server, which runs 23 preprocessing variants the
browser does not — and Safari has no detector at all.

---

## 5. First ten real cards

Expect:

- QR decodes → **VERIFIED**, ~1 s
- QR does not → **UNREADABLE** with specific advice ("too blurry", "too dark")
- ⛔ Nothing is ever auto-rejected. UNREADABLE means "try again", not "this is
  fake" — and that word must never appear in employee-facing text.

If a genuine card fails, diagnose it without the image leaving your machine:

```powershell
python scripts\diagnose_failures.py C:\aadhaar-corpus\<the folder> --compare-pipeline
```

---

## 6. Watch one number

`avs_decode_rate` in `/metrics`.

**30%** is the measured floor, from a corpus shot deliberately badly with no
guidance. Real guided uploads should be higher — but that is a prediction, not a
measurement, and the first week decides it.

Alert on `avs_decode_rate < 0.85` and `avs_certificate_days_to_expiry < 90`.

---

## What the pilot decides

| If | Then |
|---|---|
| decode rate is high | ship it. Steps 15-19 are optimising a tail you do not have |
| decode rate is low, failures are blurry/dark | the pre-check is not doing its job — fix the UI, not the AI |
| decode rate is low, failures look fine | **Step 19 (restoration)**, not Step 15 — the localiser already finds those codes and they still will not decode |

---

## Known state at handover

| | |
|---|---|
| Steps 0-14 | ✅ complete, verified aligned |
| Python tests | 720 |
| TypeScript tests | 38 |
| Real cards over real HTTP | ✅ VERIFIED, signature valid, audit chain intact |
| Contract version | 1.9.0, consistent across code and document |
| Java client compiled | ❓ never had javac |
| Browser pre-check on a device | ❓ `BarcodeDetector` has never executed |

The first two rows of "unknown" belong to your developers. Everything in AVS
itself has been exercised against real cards.
