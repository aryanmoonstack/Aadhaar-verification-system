/**
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
export const MODULES_ACROSS = 97;

/**
 * Minimum pixels per QR module before the code is unreadable.
 *
 * Server PRE_UPLOAD floor. Set BELOW the measured post-failure floor of
 * 2.74, because a false warning here costs a real person a
 * pointless retake — while post-failure the photo has already failed and a
 * false alarm is impossible.
 */
export const MIN_PX_PER_MODULE = 2.0;

/**
 * Minimum capture resolution, megapixels.
 *
 * ⛔ CORRECTED BY MEASUREMENT. This was 4 — hand-set in Step 11 from a
 *    22-image corpus where "every 2.3 MP image failed" was true. On the current
 *    27-document corpus the weakest capture that ACTUALLY DECODED measures
 *    2.31 MP, so the old value would have warned about a photo
 *    the server reads perfectly well.
 */
export const MIN_MEGAPIXELS = 2.0;

/**
 * Minimum mean brightness, 0-255.
 *
 * Server PRE_UPLOAD floor. Brightness explains a further 11% of failures on top
 * of sharpness, and unlike sharpness it IS comparable across implementations —
 * mean luminance is mean luminance.
 */
export const MIN_MEAN_BRIGHTNESS = 80.0;
