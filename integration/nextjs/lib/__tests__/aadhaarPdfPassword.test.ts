import { describe, expect, it } from 'vitest';

import { derivePdfPassword } from '../aadhaarPdfPassword';

describe('the UIDAI rule', () => {
  it('takes four characters of the name plus the birth year', () => {
    expect(derivePdfPassword({ name: 'Aaryan Sharma', birthYear: 1998 })).toBe('AARY1998');
  });

  it('uppercases', () => {
    expect(derivePdfPassword({ name: 'aaryan sharma', birthYear: 1998 })).toBe('AARY1998');
  });

  it('uses the whole name when it is shorter than four characters', () => {
    // UIDAI's stated behaviour for short names, and a plain slice happens to
    // implement it — worth pinning so a future "pad to 4" does not creep in.
    expect(derivePdfPassword({ name: 'Ria', birthYear: 1990 })).toBe('RIA1990');
    expect(derivePdfPassword({ name: 'Al', birthYear: 1990 })).toBe('AL1990');
  });

  it('keeps an interior space rather than tidying it away', () => {
    /**
     * ⛔ An Aadhaar printed "R Kumar" genuinely has the password "R KU1990".
     *    Stripping the space produces "RKUM" — wrong, and wrong in a way that
     *    looks neater, which is how it would survive review.
     */
    expect(derivePdfPassword({ name: 'R Kumar', birthYear: 1990 })).toBe('R KU1990');
  });

  it('trims surrounding whitespace, which is a storage artefact not a name', () => {
    expect(derivePdfPassword({ name: '  Aaryan Sharma  ', birthYear: 1998 })).toBe('AARY1998');
  });
});

describe('birth year, whatever shape the HRM stored it in', () => {
  it.each([
    [1998, 'AARY1998'],
    ['1998', 'AARY1998'],
    ['1998-04-21', 'AARY1998'],
    ['1998/04/21', 'AARY1998'],
    ['1998-04-21T00:00:00Z', 'AARY1998'],
  ])('accepts %s', (birthYear, expected) => {
    expect(derivePdfPassword({ name: 'Aaryan', birthYear })).toBe(expected);
  });

  it('reads day-first dates from the END, not the start', () => {
    /**
     * ⛔ The subtle one. `21-04-1998` scanned for its first four digits yields
     *    "2104" — a number that passes a "looks like a year" glance and is not
     *    one. That produces a WRONG password rather than no password, and a
     *    wrong password routes the employee to "that password was wrong" for a
     *    password the system invented.
     */
    expect(derivePdfPassword({ name: 'Aaryan', birthYear: '21-04-1998' })).toBe('AARY1998');
    expect(derivePdfPassword({ name: 'Aaryan', birthYear: '21/04/1998' })).toBe('AARY1998');
  });
});

describe('refusing to guess', () => {
  /**
   * ⚠ Every case here returns null on purpose.
   *
   *   No password produces `PDF_PASSWORD_REQUIRED` from AVS, which asks the
   *   employee for one. A malformed password produces
   *   `PDF_PASSWORD_INCORRECT`, which tells them theirs was wrong — confusing,
   *   since they never typed one. Null is the kinder failure.
   */
  it.each([
    ['no name', { name: '', birthYear: 1998 }],
    ['whitespace name', { name: '   ', birthYear: 1998 }],
    ['null name', { name: null, birthYear: 1998 }],
    ['no year', { name: 'Aaryan', birthYear: null }],
    ['empty year', { name: 'Aaryan', birthYear: '' }],
    ['unparseable year', { name: 'Aaryan', birthYear: 'unknown' }],
    ['two-digit year', { name: 'Aaryan', birthYear: '98' }],
    ['year before Aadhaar could apply', { name: 'Aaryan', birthYear: 1799 }],
    ['year in the future', { name: 'Aaryan', birthYear: new Date().getFullYear() + 1 }],
  ])('returns null for %s', (_label, input) => {
    expect(derivePdfPassword(input)).toBeNull();
  });
});

describe('what derivation cannot fix', () => {
  it('produces the wrong password when the profile name differs from the Aadhaar', () => {
    /**
     * ★ Not a bug — the reason the manual fallback exists.
     *
     *   The algorithm is trivially correct. What is uncertain is whether the
     *   HRM's name matches the one printed on the Aadhaar, and it often will
     *   not. These are the real shapes:
     */
    // Profile holds a short form; Aadhaar holds the full name.
    expect(derivePdfPassword({ name: 'Raj Sharma', birthYear: 1998 })).toBe('RAJ 1998');
    // The Aadhaar would actually be RAJK1998 — a miss, and an ordinary one.

    // Profile holds surname first.
    expect(derivePdfPassword({ name: 'Sharma Aaryan', birthYear: 1998 })).toBe('SHAR1998');
    // The Aadhaar would be AARY1998.

    // ⛔ Both are *valid outputs* of a correct function fed a different name.
    //    Nothing here can detect that, which is why a miss must route to
    //    "please enter the password", never to "that password was wrong".
  });
});
