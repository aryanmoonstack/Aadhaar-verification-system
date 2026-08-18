/**
 * EXIF presence detection — for the upload flow.
 *
 * ⛔ THE ABSENCE IS THE SIGNAL, NOT THE PRESENCE.
 *
 *    Messaging apps strip EXIF while re-encoding, and it is the RE-ENCODE that
 *    destroys QR modules — JPEG artefacts land precisely on the high-contrast
 *    module edges the decoder depends on. The photo still looks fine to a
 *    person, which is what makes this failure so confusing to the employee:
 *    they can see the code perfectly well and the machine cannot.
 *
 *    So "no EXIF, at a suspiciously round pixel size" is the fingerprint of a
 *    WhatsApp round-trip. `looksCompressed()` in captureQuality.ts combines the
 *    two signals; this supplies one of them.
 *
 * ⚠ WHY THIS IS NOT A FULL EXIF PARSER
 *
 *   The question is "was this file re-encoded", not "what camera took it". A
 *   yes/no needs the marker, not the metadata, and parsing tags would mean
 *   reading orientation, GPS and timestamps off a real person's photograph —
 *   data we have no use for and would rather never hold.
 */

/** Bytes read from the head of the file. */
const HEAD_BYTES = 65536;

/** JPEG APP1 marker — where EXIF lives. */
const APP1 = [0xff, 0xe1] as const;

/** PNG eXIf chunk type, for completeness. */
const PNG_EXIF = [0x65, 0x58, 0x49, 0x66] as const; // "eXIf"

/**
 * Does this file carry an EXIF block?
 *
 * Only the first 64KB is read — the marker sits near the start, and pulling a
 * 12MP file into memory to answer a boolean would be wasteful on the mid-range
 * Android phones this runs on.
 *
 * ⚠ Returns TRUE on error. Unknown must not be reported as "compressed":
 *   claiming a re-encode that may not have happened would show the employee a
 *   warning about a problem they do not have, and send them to retake a photo
 *   that was fine.
 */
export async function hasExif(file: Blob): Promise<boolean> {
  try {
    const head = new Uint8Array(await file.slice(0, HEAD_BYTES).arrayBuffer());
    return containsExifMarker(head);
  } catch {
    return true;
  }
}

/** The scan itself, separated so it can be tested without a Blob. */
export function containsExifMarker(head: Uint8Array): boolean {
  for (let i = 0; i < head.length - 1; i += 1) {
    if (head[i] === APP1[0] && head[i + 1] === APP1[1]) return true;
  }

  for (let i = 0; i < head.length - 3; i += 1) {
    if (
      head[i] === PNG_EXIF[0] &&
      head[i + 1] === PNG_EXIF[1] &&
      head[i + 2] === PNG_EXIF[2] &&
      head[i + 3] === PNG_EXIF[3]
    ) {
      return true;
    }
  }

  return false;
}
