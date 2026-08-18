/**
 * EXIF presence — the messaging-app fingerprint.
 *
 * ⛔ The ABSENCE of EXIF is the signal. Messaging apps strip it while
 *    re-encoding, and the re-encode is what destroys QR modules — artefacts
 *    land exactly on the high-contrast module edges the decoder needs.
 */

import { describe, expect, it } from 'vitest';

import { containsExifMarker, hasExif } from '../exif';
import { looksCompressed } from '../captureQuality';

function bytes(...values: number[]): Uint8Array {
  return new Uint8Array(values);
}

describe('containsExifMarker', () => {
  it('finds the JPEG APP1 marker', () => {
    expect(containsExifMarker(bytes(0xff, 0xd8, 0xff, 0xe1, 0x00, 0x10))).toBe(true);
  });

  it('finds the PNG eXIf chunk', () => {
    expect(containsExifMarker(bytes(0x89, 0x50, 0x4e, 0x47, 0x65, 0x58, 0x49, 0x66))).toBe(true);
  });

  it('reports absence on a stripped file', () => {
    // JPEG SOI followed by APP0/JFIF — what a re-encoder typically emits.
    expect(containsExifMarker(bytes(0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46))).toBe(false);
  });

  it('does not read past the end of a short buffer', () => {
    expect(containsExifMarker(bytes(0xff))).toBe(false);
    expect(containsExifMarker(bytes())).toBe(false);
  });
});

describe('hasExif', () => {
  it('reads only the head of the file', async () => {
    // 1MB of zeros with the marker at the very start.
    const big = new Uint8Array(1_000_000);
    big[0] = 0xff;
    big[1] = 0xe1;
    expect(await hasExif(new Blob([big]))).toBe(true);
  });

  it('⚠ returns TRUE when it cannot tell', async () => {
    // Unknown must not be reported as "compressed" — that would warn the
    // employee about a problem they may not have and send them to retake a
    // photo that was fine.
    const broken = {
      slice: () => ({ arrayBuffer: () => Promise.reject(new Error('nope')) }),
    } as unknown as Blob;

    expect(await hasExif(broken)).toBe(true);
  });
});

describe('the two signals together', () => {
  it('★ flags a WhatsApp round-trip: no EXIF at a messaging size', () => {
    expect(looksCompressed(1600, 1200, false)).toBe(true);
  });

  it('does not flag an original camera photo at the same size', () => {
    expect(looksCompressed(1600, 1200, true)).toBe(false);
  });

  it('does not flag an unusual size just because EXIF is missing', () => {
    // Size alone is weak: plenty of legitimate pipelines strip EXIF.
    expect(looksCompressed(4284, 5712, false)).toBe(false);
  });
});
