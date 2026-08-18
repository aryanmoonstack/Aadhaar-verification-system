/**
 * Capture-quality rules — Step 11.
 *
 * ⛔ These thresholds came from measuring 22 real Aadhaar photos in Step 7.5,
 *    not from intuition. The tests below encode the corpus results so a future
 *    "let's relax this a bit" has to argue with the data.
 */

import { describe, expect, it } from 'vitest';

import {
  MIN_MEGAPIXELS,
  MIN_SHARPNESS,
  MODULES_ACROSS,
  PX_PER_MODULE,
  assess,
  looksCompressed,
  megapixels,
  pxPerModule,
} from '../captureQuality';

describe('measured thresholds', () => {
  it('⛔ no longer rejects 2.3 MP — the claim it encoded stopped being true', () => {
    // ★ EXPECTATION REVERSED BY MEASUREMENT, Step 14.
    //
    // This asserted that 1920x1200 (2.3 MP) must be REFUSED, on the grounds
    // that "every image at this size failed to decode". True of the 22-image
    // corpus when it was written.
    //
    // The corpus grew to 27 documents and the weakest capture that ACTUALLY
    // DECODED now measures 2.31 MP. So the old rule warned about a photo the
    // server reads perfectly well — a false alarm, which is exactly what the
    // pre-upload thresholds exist to avoid.
    //
    // The threshold is now generated from the server, so this cannot drift
    // again without a failing test.
    const result = assess({ width: 1920, height: 1200, qrPixels: 400 });

    expect(result.issues).not.toContain('RESOLUTION_TOO_LOW');
  });

  it('still rejects a genuinely tiny capture', () => {
    // 640x480 = 0.3 MP, far below anything that has ever decoded.
    const result = assess({ width: 640, height: 480, qrPixels: 120 });

    expect(result.issues).toContain('RESOLUTION_TOO_LOW');
  });

  it('accepts a normal 12 MP phone photo', () => {
    const result = assess({ width: 4032, height: 3024, qrPixels: 500, sharpness: 120 });

    expect(result.usable).toBe(true);
    expect(result.megapixels).toBeCloseTo(12.2, 1);
  });

  it('a QR below 2 px/module is unrecoverable — measured, not assumed', () => {
    // 190px / 97 modules = 1.96
    const result = assess({ width: 4032, height: 3024, qrPixels: 190 });

    expect(result.issues).toContain('QR_TOO_SMALL');
    expect(result.usable).toBe(false);
  });

  it('a marginal QR WARNS but does not block', () => {
    // ⛔ Blocking here would turn away someone about to succeed. If the browser
    //    already decoded it, the server will too.
    const result = assess({ width: 4032, height: 3024, qrPixels: 260, sharpness: 100 });

    expect(result.issues).toContain('QR_MARGINAL');
    expect(result.usable).toBe(true);
  });

  it('rejects the blur levels that were unrecoverable in the corpus', () => {
    // phone-a-dim measured 6.7-11.7 and never decoded under any strategy.
    const result = assess({ width: 4032, height: 3024, qrPixels: 900, sharpness: 8 });

    expect(result.issues).toContain('TOO_BLURRY');
    expect(result.usable).toBe(false);
  });
});

describe('arithmetic', () => {
  it('uses the version-20 module count', () => {
    expect(MODULES_ACROSS).toBe(97);
    expect(pxPerModule(485)).toBeCloseTo(5.0, 1);
  });

  it('megapixels', () => {
    expect(megapixels(4032, 3024)).toBeCloseTo(12.19, 2);
    expect(megapixels(1920, 1200)).toBeCloseTo(2.3, 1);
  });

  it('thresholds are ordered, and the minimum sits BELOW the weakest success', () => {
    expect(PX_PER_MODULE.unrecoverable).toBeLessThan(PX_PER_MODULE.marginal);
    expect(PX_PER_MODULE.marginal).toBeLessThan(PX_PER_MODULE.good);

    // ⛔ BELOW, not above. The weakest capture that actually decoded measured
    //    2.31 MP; a floor above that would refuse a working photo. Was
    //    `toBeGreaterThan(2.3)` — the exact inversion that caused the drift.
    expect(MIN_MEGAPIXELS).toBeLessThan(2.31);
  });

  it('⛔ the generated values match the server', () => {
    // The single source of truth is `src/avs/ai/quality/assessor.py`, exported
    // by `python scripts/export_thresholds.py`. Hand-editing either side
    // recreates the drift this replaced.
    expect(MODULES_ACROSS).toBe(97);
    expect(PX_PER_MODULE.unrecoverable).toBe(2.0);
    expect(MIN_MEGAPIXELS).toBe(2.0);
  });
});

describe('messaging-app detection', () => {
  it('flags a WhatsApp-sized image with no EXIF', () => {
    expect(looksCompressed(1600, 1200, false)).toBe(true);
  });

  it('does not flag an original camera photo', () => {
    expect(looksCompressed(4032, 3024, true)).toBe(false);
  });

  it('⚠ does not flag a full-resolution image that merely lacks EXIF', () => {
    // Some legitimate cameras strip metadata. Blocking on that alone would
    // turn away valid photos, so the heuristic requires BOTH signals.
    expect(looksCompressed(4032, 3024, false)).toBe(false);
  });
});

describe('employee-facing language', () => {
  const everyOutcome = [
    assess({ width: 1920, height: 1200, qrPixels: 400 }),
    assess({ width: 4032, height: 3024, qrPixels: 150 }),
    assess({ width: 4032, height: 3024, qrPixels: 900, sharpness: 5 }),
    assess({ width: 4032, height: 3024 }),
    assess({ width: 1600, height: 1200, likelyCompressed: true }),
    assess({ width: 4032, height: 3024, qrPixels: 260, sharpness: 90 }),
    assess({ width: 4032, height: 3024, qrPixels: 600, sharpness: 200 }),
  ];

  it('⛔ never says "fake" — CONTRACTS.md §1', () => {
    for (const result of everyOutcome) {
      expect(result.guidance.toLowerCase()).not.toContain('fake');
    }
  });

  it('never blames the person, and never says "invalid" or "rejected"', () => {
    for (const result of everyOutcome) {
      const text = result.guidance.toLowerCase();
      expect(text).not.toContain('invalid');
      expect(text).not.toContain('rejected');
      expect(text).not.toContain('failed');
    }
  });

  it('gives ONE actionable instruction, not a list of symptoms', () => {
    // A photo that is small, blurry AND far away has one fix, not three.
    const result = assess({ width: 1280, height: 960, qrPixels: 100, sharpness: 4 });

    expect(result.guidance.split('.').filter((s) => s.trim()).length).toBeLessThanOrEqual(2);
  });

  it('tells a compressed upload to retake with the camera', () => {
    const result = assess({ width: 1600, height: 1200, likelyCompressed: true });
    expect(result.guidance).toMatch(/camera/i);
  });
});
