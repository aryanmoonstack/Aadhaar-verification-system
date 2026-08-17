# Next.js upload flow — Step 11

Two-sided Aadhaar capture with an **in-browser readability check** before upload.

---

## Why this step exists

The measured decode rate on 22 real Aadhaar photos was **22.7%**.

Step 7.5 made the server five times faster and got all 23 preprocessing
strategies actually running — and the rate **did not move**. Because the
failures were never a processing problem:

| | decoded | |
|---|---|---|
| 12.2 MP images | 5/14 | 36% |
| **2.3 MP images** | **0/8** | **0%** |

2.3 MP is what WhatsApp, Telegram and "compress before sending" produce. At that
size the Secure QR lands near 200px ≈ 2 pixels per module, which is the floor
below which a dense QR is unrecoverable. **No server-side work invents
information that is not in the file.**

The only place that can be fixed is where the photo is taken. So this UI decodes
the QR **in the browser, before upload**. If the browser can read it, the server
will too. If it cannot, the person is told in ~50ms while the camera is still
open — instead of after an 8-second round trip ending in "please try again".

---

## ⛔ Three rules this code will not bend

**The browser never talks to AVS directly.** Calling AVS needs an HMAC
signature, and a browser cannot hold a signing secret — anything shipped to the
client is public, however it is obfuscated. Images go to the HRM, which signs
server-side. A refactor that "simplifies" this by calling AVS from the client
puts your tenant key in a JavaScript bundle.

**The pre-check is never a verdict.** The browser decodes only to answer *"is
this photo good enough to send?"* It does not verify the signature and cannot
approve anything. `PrecheckResult` deliberately has no `verified` or
`signatureValid` field, and a test asserts that. Verification is an RSA check
against UIDAI's public key on the server — CONTRACTS.md §1 Rule 1.

**The decoded payload never leaves the device.** It is a person's signed
demographic record. We take its length to judge readability and drop it; only
the image is uploaded, and the server decodes it again itself.

---

## Files

| | |
|---|---|
| `lib/qrPrecheck.ts` | In-browser decode. `BarcodeDetector` with a lazy `zxing-wasm` fallback |
| `lib/captureQuality.ts` | Resolution, blur and px-per-module rules — all from Step 7.5 measurements |
| `components/AadhaarCapture.tsx` | Two-sided capture with live guidance |
| `app/api/aadhaar/verify/route.ts` | Session-authenticated proxy to the Spring backend |

```bash
npm install
npm run typecheck   # tsc --strict
npm test            # 27 tests
```

`zxing-wasm` is an **optional** peer dependency — only Safari and Firefox load
it. Install it if you support those:

```bash
npm install zxing-wasm
```

---

## Capture details that decide whether this works

**Ask for maximum camera resolution.** `width: { ideal: 3840 }`. A
default-resolution stream is often exactly the 2.3 MP that failed 8 out of 8.
`ideal` rather than `exact`, so a modest camera still works.

**JPEG quality 0.95, not the 0.8 default.** JPEG artefacts land precisely on the
high-contrast edges that define QR modules. A code that decodes at 0.95 can fail
at 0.8, and the extra bytes are far cheaper than a re-upload.

**Pre-check every 600ms, not every frame.** Native detection takes ~50ms but the
WASM fallback is much slower. Running it continuously drains the battery and
makes the preview stutter — which makes the camera harder to hold steady, and
causes the very blur we are trying to avoid.

**Both faces, either order, QR on either side.** The signature covers the QR
payload only, never the printed face, so one image cannot be a complete
document — CONTRACTS.md §11. Placement varies by card format, so requiring the
code on a *specific* side would turn away a large share of genuine cards.

---

## Language

⛔ **The word "fake" never appears in anything an employee sees** —
CONTRACTS.md §1. A genuine card photographed badly is indistinguishable from a
forgery to any automated check, which is exactly why no automated check may call
it one.

Every message describes what the *camera* should do differently:

> Move closer so the square code fills more of the frame.
>
> This photo has been compressed — please take a new one with the camera rather
> than sharing from a chat app.
>
> That code is not the signed one — try the other side of the card.

Tests assert that no guidance string contains "fake", "invalid", "rejected" or
"failed", and that each gives **one** actionable instruction rather than a list
of symptoms. A photo that is small, blurry *and* far away has one fix, not three.

---

## Accessibility

The live guidance is in an `aria-live="polite"` region. Someone using a screen
reader cannot see the camera preview at all, so "move closer" has to be
announced rather than merely displayed.

If the camera cannot be opened — permission denied, no camera, insecure origin —
the flow degrades to file upload rather than dead-ending.

---

## What this does not fix

Roughly a quarter of the corpus failures were **severe motion blur** (measured
Laplacian variance 6–12). Those are caught and refused here, which is the right
outcome, but the person still has to retake the photo. Steps 14 and 16 add a
quality model and on-device guidance that should reduce how often that happens.

The pre-check is unavailable on Safari and Firefox unless `zxing-wasm` is
installed. When no detector is available, **upload is still allowed** — refusing
because *our* accelerator is missing would lock those users out entirely, and
the server decodes anyway.
