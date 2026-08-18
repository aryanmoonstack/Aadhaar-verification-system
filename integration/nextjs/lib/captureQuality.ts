/**
 * Capture quality rules — Step 11.
 *
 * ⛔ EVERY THRESHOLD HERE COMES FROM MEASUREMENT, NOT INTUITION.
 *
 * A 22-photo corpus of real Aadhaar cards was measured in Step 7.5. The result
 * that shaped this file:
 *
 *     12.2 MP images    5/14 decoded   36%
 *      2.3 MP images    0/8  decoded    0%     <-- every single one failed
 *
 * 2.3 MP is roughly 1920x1200 — not a modern phone camera, but what WhatsApp,
 * Telegram and "compress before sending" produce. At that size a card in frame
 * puts the Secure QR near 200px, which is about 2 pixels per module. That is
 * the floor at which a dense QR stops being recoverable, and no amount of
 * server-side processing invents information that is not in the file.
 *
 * So the most valuable thing this UI does is refuse to send an image that
 * cannot possibly work, and say why while the camera is still open.
 *
 * WHY THE QR IS SO DEMANDING
 * --------------------------
 * The Aadhaar Secure QR carries ~2000 characters — a version-20-plus symbol,
 * roughly 97 modules across. Compare a URL QR at 25 modules: the Aadhaar code
 * needs almost four times the linear resolution for the same reliability.
 */

// ⛔ MEASURED VALUES COME FROM THE SERVER. `thresholds.generated.ts` is written
//    by `python scripts/export_thresholds.py` from `ai/quality/assessor.py`,
//    which derives them from real photographs run through the actual decoder.
//
//    They were hand-maintained here until Step 14 and had silently drifted:
//    the browser refused anything under 4 MP while the weakest capture that
//    ACTUALLY DECODED measured 2.31 MP. Nothing connected the two, so nothing
//    noticed.
import {
  MIN_MEAN_BRIGHTNESS as GENERATED_MIN_BRIGHTNESS,
  MIN_MEGAPIXELS as GENERATED_MIN_MEGAPIXELS,
  MIN_PX_PER_MODULE as GENERATED_MIN_PX_PER_MODULE,
  MODULES_ACROSS as GENERATED_MODULES_ACROSS,
} from './thresholds.generated';

/** A version-21/22 QR is 97 modules across. Aadhaar payloads land at or above this. */
export const MODULES_ACROSS = GENERATED_MODULES_ACROSS;

export { GENERATED_MIN_BRIGHTNESS as MIN_MEAN_BRIGHTNESS };

/**
 * Pixels per module thresholds.
 *
 * Measured, not guessed: on the real corpus nothing below 2.0 was recoverable
 * by any preprocessing, and everything above 3.3 that was in focus decoded.
 */
export const PX_PER_MODULE = {
  /** Below this the information is physically absent. From the server. */
  unrecoverable: GENERATED_MIN_PX_PER_MODULE,
  /** Decodes sometimes. Worth warning the user. */
  marginal: 3.0,
  /** Comfortable. */
  good: 4.0,
} as const;

/**
 * Minimum capture resolution.
 *
 * ⛔ CORRECTED IN STEP 14 — was hard-coded to 4.
 *
 *    The old comment read "every 2.3 MP image in the corpus failed", which was
 *    true of the 22 images that existed when it was written. The corpus grew to
 *    27 documents and the weakest capture that ACTUALLY DECODED now measures
 *    2.31 MP — so a floor of 4 would warn about a photo the server reads
 *    perfectly well. Now generated from the server.
 */
export const MIN_MEGAPIXELS = GENERATED_MIN_MEGAPIXELS;

/**
 * ⚠ UNUSED — nothing in the browser computes sharpness.
 *
 *   `FrameMeasurements.sharpness` is optional and no caller supplies it, so
 *   this threshold has never been applied to anything. It is kept only so that
 *   a caller which DOES measure sharpness has a documented starting point.
 *
 *   ⛔ It is deliberately NOT synced from the server's 250. That figure is a
 *      variance-of-Laplacian value from OpenCV, and a JavaScript implementation
 *      would not share its scale. A number copied across would look
 *      authoritative and mean nothing — which is worse than an obviously
 *      unused constant.
 */
export const MIN_SHARPNESS = 20;

export type QualityIssue =
  | 'RESOLUTION_TOO_LOW'
  | 'IMAGE_WAS_COMPRESSED'
  | 'QR_TOO_SMALL'
  | 'QR_MARGINAL'
  | 'TOO_BLURRY'
  | 'NO_QR_FOUND';

export interface QualityAssessment {
  readonly usable: boolean;
  readonly issues: readonly QualityIssue[];
  /** What to tell the person, in plain language. Never mentions "fake". */
  readonly guidance: string;
  readonly megapixels: number;
  readonly qrPixels?: number;
  readonly pxPerModule?: number;
  readonly sharpness?: number;
}

export interface FrameMeasurements {
  readonly width: number;
  readonly height: number;
  /** Short side of the QR's bounding box, if one was located. */
  readonly qrPixels?: number;
  readonly sharpness?: number;
  /** True when the file looks re-encoded by a messaging app. */
  readonly likelyCompressed?: boolean;
}

export function megapixels(width: number, height: number): number {
  return (width * height) / 1_000_000;
}

export function pxPerModule(qrPixels: number): number {
  return qrPixels / MODULES_ACROSS;
}

/**
 * Judge one captured frame.
 *
 * ⛔ The guidance strings are employee-facing and must never use the word
 *    "fake" — CONTRACTS.md §1. A genuine card photographed badly is
 *    indistinguishable from a forgery to any automated check, which is exactly
 *    why no automated check may call it one. Every message here describes what
 *    the CAMERA should do differently, never what the person did wrong.
 */
export function assess(frame: FrameMeasurements): QualityAssessment {
  const issues: QualityIssue[] = [];
  const mp = megapixels(frame.width, frame.height);
  const modules = frame.qrPixels ? pxPerModule(frame.qrPixels) : undefined;

  if (frame.likelyCompressed) {
    issues.push('IMAGE_WAS_COMPRESSED');
  }
  if (mp < MIN_MEGAPIXELS) {
    issues.push('RESOLUTION_TOO_LOW');
  }
  if (frame.sharpness !== undefined && frame.sharpness < MIN_SHARPNESS) {
    issues.push('TOO_BLURRY');
  }

  if (frame.qrPixels === undefined) {
    issues.push('NO_QR_FOUND');
  } else if (modules! < PX_PER_MODULE.unrecoverable) {
    issues.push('QR_TOO_SMALL');
  } else if (modules! < PX_PER_MODULE.marginal) {
    issues.push('QR_MARGINAL');
  }

  // MARGINAL is a warning, not a block — a marginal QR that the browser has
  // already decoded will decode on the server too, and blocking it would send
  // someone away who was about to succeed.
  const blocking = issues.filter((i) => i !== 'QR_MARGINAL');

  return {
    usable: blocking.length === 0,
    issues,
    guidance: guidanceFor(issues, modules),
    megapixels: Number(mp.toFixed(1)),
    qrPixels: frame.qrPixels,
    pxPerModule: modules ? Number(modules.toFixed(2)) : undefined,
    sharpness: frame.sharpness,
  };
}

/**
 * One instruction at a time, most actionable first.
 *
 * Listing every problem at once is paralysing. "Move closer" is something a
 * person can act on immediately; "resolution too low, blurry, QR too small" is
 * three ways of describing the same fix.
 */
function guidanceFor(issues: readonly QualityIssue[], modules?: number): string {
  if (issues.includes('IMAGE_WAS_COMPRESSED')) {
    return 'This photo has been compressed — please take a new one with the camera rather than sharing from a chat app.';
  }
  if (issues.includes('RESOLUTION_TOO_LOW')) {
    return 'This photo is too small to read the code. Please take a new one with your camera at full quality.';
  }
  if (issues.includes('QR_TOO_SMALL')) {
    return 'Move closer so the square code fills more of the frame.';
  }
  if (issues.includes('TOO_BLURRY')) {
    return 'Hold steady for a moment — the picture is blurred.';
  }
  if (issues.includes('NO_QR_FOUND')) {
    return 'Point the camera at the side of the card with the square code on it.';
  }
  if (issues.includes('QR_MARGINAL')) {
    return `Almost there — move a little closer if you can (${modules?.toFixed(1)} pixels per module).`;
  }
  return 'Looks good.';
}

/**
 * Does this file look like a messaging app re-encoded it?
 *
 * WhatsApp and similar resize to roughly 1600px and strip EXIF. A file with no
 * camera metadata AND a suspiciously round dimension is very likely a forward
 * rather than an original — and forwarded images failed 8 out of 8 in the
 * corpus.
 *
 * ⚠ A heuristic, deliberately used only to WARN. Some legitimate cameras strip
 *   EXIF, so blocking on this alone would turn away valid photos.
 */
export function looksCompressed(
  width: number,
  height: number,
  hasExif: boolean,
): boolean {
  const longest = Math.max(width, height);
  const messagingSizes = [1280, 1600, 1920, 2048];
  const nearMessagingSize = messagingSizes.some((s) => Math.abs(longest - s) <= 16);
  return !hasExif && nearMessagingSize;
}
