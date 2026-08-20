/**
 * Deriving the password of an e-Aadhaar PDF from the employee's profile.
 *
 * ★ WHY BOTHER
 *
 *   An e-Aadhaar downloaded from UIDAI is encrypted, and most employees do not
 *   know it has a password at all — let alone what it is. Asking first turns a
 *   two-second task into a support ticket. The HRM already holds the name and
 *   date of birth, so in the common case the password can simply be computed
 *   and the employee never sees a password box.
 *
 *   UIDAI's rule: the first four characters of the name **as printed on the
 *   Aadhaar**, in capitals, followed by the four-digit year of birth.
 *
 *       "Aaryan Sharma", 1998  ->  AARY1998
 *       "Ria", 1990            ->  RIA1990     (names under four characters
 *                                               use the whole name)
 *
 * ⛔ THIS IS A CONVENIENCE, NOT A GUARANTEE — AND THE FALLBACK IS THE FEATURE.
 *
 *    The algorithm is trivially correct. What is not guaranteed is that the
 *    HRM's name equals the Aadhaar's name:
 *
 *      profile "Raj Sharma"    aadhaar "Rajkumar Sharma"  -> RAJ_ vs RAJK
 *      profile "Sharma Aaryan" aadhaar "Aaryan Sharma"    -> SHAR vs AARY
 *      profile "R Kumar"       aadhaar "Ramesh Kumar"     -> R KU vs RAME
 *
 *    So a miss is ordinary, not exceptional. When it happens the employee must
 *    be ASKED for the password — and asked as a first request, never told
 *    "wrong password", because they never typed one.
 *
 * ⛔ NEVER LOG THE RESULT, AND NEVER WRITE A DECRYPTED PDF TO DISK.
 *
 *    The derived string contains part of a real name and a real birth year.
 *    It is passed to AVS in memory and discarded. Decrypting the PDF and saving
 *    an unlocked copy — the obvious-looking approach — would leave a readable
 *    Aadhaar sitting in a temp directory, which is exactly what UIDAI encrypted
 *    it to prevent.
 */

/** The name portion is four characters. UIDAI's rule, not an arbitrary choice. */
const NAME_CHARS = 4;

/** Aadhaar has existed since 2009; nobody enrolled has a birth year outside this. */
const EARLIEST_YEAR = 1900;
const LATEST_YEAR = new Date().getFullYear();

export interface DeriveInput {
  /** The employee's name, ideally exactly as it appears on their Aadhaar. */
  readonly name: string | null | undefined;
  /** Year of birth. Accepts a number, "1998", or a full date like "1998-04-21". */
  readonly birthYear: string | number | null | undefined;
}

/**
 * Build the password, or return null when the profile cannot support one.
 *
 * ⚠ Returns null rather than a partial guess. Submitting a malformed password
 *   produces `PDF_PASSWORD_INCORRECT`, which routes the employee to "that
 *   password was wrong" — a confusing thing to read when the system invented
 *   the password itself. No password at all produces `PDF_PASSWORD_REQUIRED`,
 *   which correctly asks them for one.
 */
export function derivePdfPassword(input: DeriveInput): string | null {
  const year = normaliseYear(input.birthYear);
  if (year === null) return null;

  // ⚠ Trimmed, but NOT stripped of interior spaces or punctuation. The rule is
  //   the first four characters of the name as printed, and an Aadhaar reading
  //   "R Kumar" genuinely has the password "R KU1990". Removing the space would
  //   produce "RKUM" — wrong, and wrong in a way that looks tidier.
  const name = (input.name ?? '').trim();
  if (name.length === 0) return null;

  // Names shorter than four characters use the whole name.
  const prefix = name.slice(0, NAME_CHARS).toUpperCase();

  return `${prefix}${year}`;
}

/**
 * Pull a four-digit year out of whatever the profile stores.
 *
 * ⚠ HRM date fields are rarely consistent — a `Date`, an ISO string, a
 *   display-formatted string. Accepting the common shapes here beats each
 *   caller reaching for its own substring.
 */
function normaliseYear(value: string | number | null | undefined): string | null {
  if (value === null || value === undefined) return null;

  if (typeof value === 'number') {
    return inRange(value) ? String(value) : null;
  }

  const text = value.trim();
  if (text.length === 0) return null;

  // Plain year.
  if (/^\d{4}$/.test(text)) {
    return inRange(Number(text)) ? text : null;
  }

  // ISO-ish: 1998-04-21, 1998/04/21, 1998-04-21T00:00:00Z
  const leading = text.match(/^(\d{4})[-/]/);
  if (leading?.[1]) {
    return inRange(Number(leading[1])) ? leading[1] : null;
  }

  // ⚠ Day-first display formats: 21-04-1998, 21/04/1998.
  //   Taking the FIRST four digits here would yield "2104" — a plausible-looking
  //   year that is not one, producing a wrong password rather than no password.
  const trailing = text.match(/(\d{4})\s*$/);
  if (trailing?.[1]) {
    return inRange(Number(trailing[1])) ? trailing[1] : null;
  }

  return null;
}

function inRange(year: number): boolean {
  return Number.isInteger(year) && year >= EARLIEST_YEAR && year <= LATEST_YEAR;
}
