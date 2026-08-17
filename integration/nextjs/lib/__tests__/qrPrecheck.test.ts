/**
 * In-browser pre-check — Step 11.
 *
 * ⛔ The pre-check must never become a verdict. These tests pin that boundary
 *    as much as they pin the detection logic.
 */

import { describe, expect, it } from 'vitest';

import {
  MIN_SECURE_QR_DIGITS,
  isSecureQrPayload,
  precheckMessage,
  type PrecheckResult,
} from '../qrPrecheck';

const digits = (n: number) => '7'.repeat(n);

describe('Secure QR identification', () => {
  it('accepts a realistic Aadhaar payload', () => {
    // Real corpus payloads measured 3000-3499 digits.
    expect(isSecureQrPayload(digits(3142))).toBe(true);
  });

  it('rejects a URL QR', () => {
    expect(isSecureQrPayload('https://myaadhaar.uidai.gov.in/x')).toBe(false);
  });

  it('rejects the short non-Secure code some card faces carry', () => {
    expect(isSecureQrPayload(digits(40))).toBe(false);
  });

  it('rejects a long NON-numeric string', () => {
    // Length alone is not enough — the Secure QR is a decimal integer.
    expect(isSecureQrPayload('a'.repeat(3000))).toBe(false);
  });

  it('uses the same digit floor as the server', () => {
    expect(MIN_SECURE_QR_DIGITS).toBe(500);
    expect(isSecureQrPayload(digits(499))).toBe(false);
    expect(isSecureQrPayload(digits(500))).toBe(true);
  });

  it('tolerates surrounding whitespace', () => {
    expect(isSecureQrPayload(`  ${digits(3000)}\n`)).toBe(true);
  });
});

describe('guidance', () => {
  const result = (o: PrecheckResult['outcome']): PrecheckResult => ({
    outcome: o,
    readable: o === 'SECURE_QR_READABLE',
    detector: 'BarcodeDetector',
    elapsedMs: 40,
  });

  it('⛔ never says "fake"', () => {
    const outcomes: PrecheckResult['outcome'][] = [
      'SECURE_QR_READABLE',
      'WRONG_QR_ON_THIS_FACE',
      'NO_QR_FOUND',
      'DETECTOR_UNAVAILABLE',
    ];
    for (const o of outcomes) {
      expect(precheckMessage(result(o)).toLowerCase()).not.toContain('fake');
    }
  });

  it('a wrong QR points at the OTHER SIDE rather than reporting failure', () => {
    // The QR may be on either face; telling someone "no code found" when they
    // are plainly pointing at a code is baffling.
    expect(precheckMessage(result('WRONG_QR_ON_THIS_FACE'))).toMatch(/other side/i);
  });

  it('⚠ an unavailable detector does not blame the photo', () => {
    // Safari has no BarcodeDetector. That is our limitation, not the user's,
    // and upload must still proceed.
    const message = precheckMessage(result('DETECTOR_UNAVAILABLE'));
    expect(message).toMatch(/after upload/i);
    expect(message.toLowerCase()).not.toContain('error');
  });
});

describe('the pre-check is NOT a verdict', () => {
  it('readable is true ONLY for a Secure QR', () => {
    const outcomes: PrecheckResult['outcome'][] = [
      'WRONG_QR_ON_THIS_FACE',
      'NO_QR_FOUND',
      'DETECTOR_UNAVAILABLE',
    ];
    for (const outcome of outcomes) {
      const r: PrecheckResult = { outcome, readable: false, detector: 'none', elapsedMs: 1 };
      expect(r.readable).toBe(false);
    }
  });

  it('⛔ the result type carries no verdict and no signature claim', () => {
    // If someone ever adds `verified` or `signatureValid` here, the browser
    // starts making a claim only an RSA check against UIDAI's key may make.
    const r: PrecheckResult = {
      outcome: 'SECURE_QR_READABLE',
      readable: true,
      payloadLength: 3142,
      detector: 'BarcodeDetector',
      elapsedMs: 40,
    };
    expect(Object.keys(r)).not.toContain('verdict');
    expect(Object.keys(r)).not.toContain('verified');
    expect(Object.keys(r)).not.toContain('signatureValid');
  });

  it('⛔ reports a payload LENGTH, never the payload', () => {
    // The decoded payload is a signed demographic record. It stays on-device.
    const r: PrecheckResult = {
      outcome: 'SECURE_QR_READABLE',
      readable: true,
      payloadLength: 3142,
      detector: 'BarcodeDetector',
      elapsedMs: 40,
    };
    expect(typeof r.payloadLength).toBe('number');
    expect(Object.keys(r)).not.toContain('payload');
    expect(Object.keys(r)).not.toContain('rawValue');
  });
});
