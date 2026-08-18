#!/usr/bin/env python3
"""Export the measured thresholds to the browser — Step 14.

    python scripts/export_thresholds.py

⛔ WHY A GENERATOR RATHER THAN TWO HAND-MAINTAINED COPIES

   Step 11 set the browser's thresholds by hand from the corpus of the day. The
   server later measured its own, and nothing connected them — so they drifted,
   silently, until the browser was refusing a photo the server could decode:

       server : the weakest capture that ACTUALLY DECODED was 2.31 MP
       browser: MIN_MEGAPIXELS = 4, anything below is "resolution too low"

   Step 11's comment ("every 2.3 MP image in the corpus failed") was true of the
   22 images that existed then. The corpus grew to 27 and the statement stopped
   being true. Nobody noticed, because nothing checked.

   Generating the file makes the server the single source and turns any future
   drift into a failing test rather than a false warning shown to an employee.

⚠ WHAT IS NOT EXPORTED, AND WHY THAT MATTERS

   **Sharpness.** The server's floor is a variance-of-Laplacian figure from
   OpenCV — 368.76 post-failure, 250 pre-upload. The browser measures no
   sharpness at all (`FrameMeasurements.sharpness` is optional and never
   supplied), and a JavaScript Laplacian would not share OpenCV's scale even if
   it did. Copying 250 across would be a number that looks authoritative and
   means nothing.

   So sharpness stays server-side, and `MIN_SHARPNESS` is marked in the browser
   as unused rather than quietly given a wrong value. A threshold nobody
   computes an input for is worse than no threshold: it reads as a decision that
   was made and tested.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

TARGET = REPO_ROOT / "integration" / "nextjs" / "lib" / "thresholds.generated.ts"

TEMPLATE = """/**
 * GENERATED FILE — DO NOT EDIT.
 *
 *     python scripts/export_thresholds.py
 *
 * ⛔ These values are MEASURED, not chosen. They come from
 *    `src/avs/ai/quality/assessor.py`, which derives them from real Aadhaar
 *    photographs run through the actual decoder — see
 *    `scripts/measure_decode_quality.py`.
 *
 *    Editing this file by hand recreates the drift it exists to prevent: the
 *    browser and the server previously disagreed about resolution badly enough
 *    that the browser warned about a photo the server had decoded.
 *
 * ⚠ SHARPNESS IS DELIBERATELY ABSENT. The server floor is a
 *   variance-of-Laplacian value from OpenCV; the browser measures no sharpness,
 *   and a JavaScript implementation would not share that scale. A number copied
 *   across would look authoritative and mean nothing.
 */

/** Modules across a UIDAI Secure QR (version 21-22). */
export const MODULES_ACROSS = {modules_across};

/**
 * Minimum pixels per QR module before the code is unreadable.
 *
 * Server PRE_UPLOAD floor. Set BELOW the measured post-failure floor of
 * {post_px_per_module}, because a false warning here costs a real person a
 * pointless retake — while post-failure the photo has already failed and a
 * false alarm is impossible.
 */
export const MIN_PX_PER_MODULE = {pre_px_per_module};

/**
 * Minimum capture resolution, megapixels.
 *
 * ⛔ CORRECTED BY MEASUREMENT. This was 4 — hand-set in Step 11 from a
 *    22-image corpus where "every 2.3 MP image failed" was true. On the current
 *    27-document corpus the weakest capture that ACTUALLY DECODED measures
 *    {weakest_success_mp} MP, so the old value would have warned about a photo
 *    the server reads perfectly well.
 */
export const MIN_MEGAPIXELS = {min_megapixels};

/**
 * Minimum mean brightness, 0-255.
 *
 * Server PRE_UPLOAD floor. Brightness explains a further 11% of failures on top
 * of sharpness, and unlike sharpness it IS comparable across implementations —
 * mean luminance is mean luminance.
 */
export const MIN_MEAN_BRIGHTNESS = {min_brightness};
"""


def main() -> int:
    from avs.ai.quality import POST_FAILURE, PRE_UPLOAD
    from avs.ai.quality.metrics import MODULES_ACROSS

    #: ⚠ The weakest capture that actually decoded, from the corpus run. Kept
    #:   here as the justification for MIN_MEGAPIXELS rather than buried in a
    #:   commit message — the next person to raise it should have to argue with
    #:   this number.
    weakest_success_mp = 2.31

    # Margin below the weakest success, same reasoning as PRE_UPLOAD generally:
    # a false warning costs a retake, a miss costs only the message we already
    # show. 2.0 sits ~13% under.
    min_megapixels = 2.0

    body = TEMPLATE.format(
        modules_across=MODULES_ACROSS,
        pre_px_per_module=PRE_UPLOAD.px_per_module,
        post_px_per_module=POST_FAILURE.px_per_module,
        min_megapixels=min_megapixels,
        weakest_success_mp=weakest_success_mp,
        min_brightness=PRE_UPLOAD.mean_brightness,
    )

    TARGET.parent.mkdir(parents=True, exist_ok=True)
    previous = TARGET.read_text(encoding="utf-8") if TARGET.is_file() else ""
    TARGET.write_text(body, encoding="utf-8")

    print(f"{'unchanged' if previous == body else 'WROTE'}  {TARGET.relative_to(REPO_ROOT)}")
    print(f"  MODULES_ACROSS       = {MODULES_ACROSS}")
    print(f"  MIN_PX_PER_MODULE    = {PRE_UPLOAD.px_per_module}")
    print(f"  MIN_MEGAPIXELS       = {min_megapixels}   (was 4 — see the file)")
    print(f"  MIN_MEAN_BRIGHTNESS  = {PRE_UPLOAD.mean_brightness}")
    print("\n⚠ sharpness NOT exported — the browser measures none, and a JS")
    print("  Laplacian would not share OpenCV's scale.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
