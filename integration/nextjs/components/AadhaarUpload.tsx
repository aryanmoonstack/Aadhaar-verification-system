'use client';

/**
 * Two-sided Aadhaar UPLOAD — file picker, not a camera.
 *
 * ⛔ WHY THIS EXISTS ALONGSIDE `AadhaarCapture.tsx`
 *
 *    Step 11 shipped a live-camera component. M-One HRM offers file upload, not
 *    in-app capture, so that component does not fit the product: it opens
 *    `getUserMedia` and has no file input at all.
 *
 *    The valuable part of Step 11 was never the camera. `precheck()` accepts an
 *    `ImageBitmapSource`, and `File` extends `Blob`, so it runs on a picked file
 *    unchanged. `assess()` takes plain numbers. Both libraries are reused here
 *    verbatim — only the shell differs.
 *
 * ⛔ THE BROWSER NEVER TALKS TO AVS DIRECTLY.
 *
 *    Calling AVS requires an HMAC signature, and a browser cannot hold a signing
 *    secret — anything shipped to the client is public. Files go to the HRM,
 *    which signs server-side and forwards. A "simplifying" refactor that lets
 *    the browser call AVS would put the tenant key in a JavaScript bundle.
 *
 * ⛔ BOTH FACES ARE REQUIRED — CONTRACTS.md §11.
 *
 *    The UIDAI signature covers the QR payload only, never the printed card
 *    face. A genuine back paired with a forged front would otherwise sail
 *    through: the signature really does verify, because it says nothing about
 *    the face beside it. And the QR may be on EITHER side — card formats vary,
 *    so a UI demanding "the QR is on the back" would turn away genuine cards.
 *
 * WHAT THE PRE-CHECK BUYS IN AN UPLOAD FLOW
 * -----------------------------------------
 * The measured decode rate on real photos is 30%. Server-side work in Step 7.5
 * made everything five times faster and moved that number not at all, because
 * the failures were photographs that could never have worked.
 *
 * Here the browser decodes the chosen file BEFORE it is sent — about 50ms with
 * the native detector. On a 12MP file over mobile data that replaces "upload
 * for 30 seconds, wait, get rejected" with an answer that arrives instantly.
 *
 * ⚠ HONEST LIMITATION versus live capture. The photo already exists by the time
 *   this runs, so guidance is retrospective: "that one will not work, choose
 *   another" rather than "move closer" while framing. 29% of measured failures
 *   were "too far back", which in-the-moment guidance would have prevented and
 *   this can only catch after the fact. That is the cost of upload-only, and it
 *   is a product decision, not a technical limit.
 */

import { useCallback, useRef, useState, type ChangeEvent } from 'react';

import { assess, looksCompressed, type QualityAssessment } from '../lib/captureQuality';
import { hasExif } from '../lib/exif';
import { precheck, precheckMessage, type PrecheckResult } from '../lib/qrPrecheck';

type Side = 'front' | 'back';

interface ChosenFile {
  readonly file: File;
  readonly preview: string;
  readonly quality: QualityAssessment;
  readonly precheck: PrecheckResult;
}

export interface AadhaarUploadProps {
  /** Where the HRM accepts the upload. ⛔ Never an AVS URL. */
  readonly uploadUrl?: string;
  readonly onSubmitted?: (jobId: string) => void;
}

export function AadhaarUpload({
  uploadUrl = '/api/aadhaar/verify',
  onSubmitted,
}: AadhaarUploadProps) {
  const [front, setFront] = useState<ChosenFile | null>(null);
  const [back, setBack] = useState<ChosenFile | null>(null);
  const [busy, setBusy] = useState(false);
  const [checking, setChecking] = useState<Side | null>(null);
  const [error, setError] = useState<string | null>(null);

  const frontInput = useRef<HTMLInputElement>(null);
  const backInput = useRef<HTMLInputElement>(null);

  const inspect = useCallback(async (side: Side, file: File) => {
    setChecking(side);
    setError(null);
    try {
      // ⚠ `createImageBitmap` on the File gives real pixel dimensions. The
      //   `width`/`height` a browser reports for an <img> can be affected by
      //   EXIF orientation, and a rotated 12MP photo misreported as portrait
      //   would change the megapixel maths.
      const bitmap = await createImageBitmap(file);
      const { width, height } = bitmap;

      // ⛔ Runs on the FILE. `precheck` takes an ImageBitmapSource and File
      //    extends Blob, so no camera and no conversion is involved.
      const result = await precheck(bitmap);

      // ⚠ EXIF is stripped by messaging apps. Its absence at a suspiciously
      //   round size is the signature of a WhatsApp re-encode, which destroys
      //   QR modules while leaving the photo looking fine to a person.
      const compressed = looksCompressed(width, height, await hasExif(file));

      const quality = assess({
        width,
        height,
        qrPixels: result.qrPixels,
        likelyCompressed: compressed,
      });

      bitmap.close?.();

      const chosen: ChosenFile = {
        file,
        preview: URL.createObjectURL(file),
        quality,
        precheck: result,
      };
      (side === 'front' ? setFront : setBack)(chosen);
    } catch {
      // ⛔ A pre-check failure must never block the upload. The server decodes
      //    anyway; this was only ever an accelerator. Refusing here because OUR
      //    check broke would turn a working submission into a dead end.
      const chosen: ChosenFile = {
        file,
        preview: URL.createObjectURL(file),
        quality: {
          usable: true,
          issues: [],
          guidance: 'We could not check this photo here — you can still upload it.',
          megapixels: 0,
        },
        precheck: {
          outcome: 'DETECTOR_UNAVAILABLE',
          readable: false,
          detector: 'none',
          elapsedMs: 0,
        },
      };
      (side === 'front' ? setFront : setBack)(chosen);
    } finally {
      setChecking(null);
    }
  }, []);

  const onPick = useCallback(
    (side: Side) => (event: ChangeEvent<HTMLInputElement>) => {
      const file = event.target.files?.[0];
      if (file) void inspect(side, file);
    },
    [inspect],
  );

  const submit = useCallback(async () => {
    if (!front || !back) return;
    setBusy(true);
    setError(null);
    try {
      const form = new FormData();
      form.append('front', front.file, front.file.name || 'front.jpg');
      form.append('back', back.file, back.file.name || 'back.jpg');

      // The HRM signs and forwards. The browser holds no secret.
      const response = await fetch(uploadUrl, { method: 'POST', body: form });
      const body = await response.json();

      if (response.ok && body.jobId) {
        onSubmitted?.(body.jobId);
      } else {
        setError('Upload failed. Please try again.');
      }
    } catch {
      setError('Upload failed. Please check your connection and try again.');
    } finally {
      setBusy(false);
    }
  }, [front, back, uploadUrl, onSubmitted]);

  // ⛔ UPLOAD IS NEVER BLOCKED — only advised.
  //
  //    A photo the browser cannot read may still decode on the server, which
  //    runs 23 preprocessing variants the browser does not. And on Safari the
  //    detector is simply absent. Disabling the button on a failed pre-check
  //    would lock those people out of the product entirely.
  const ready = front !== null && back !== null;

  return (
    <div>
      <h2>Upload your Aadhaar</h2>
      <p>Photos of both sides. Whichever side has the QR code, we will find it.</p>

      {(['front', 'back'] as const).map((side) => {
        const chosen = side === 'front' ? front : back;
        const input = side === 'front' ? frontInput : backInput;

        return (
          <section key={side} aria-labelledby={`${side}-heading`}>
            <h3 id={`${side}-heading`}>{side === 'front' ? 'Front' : 'Back'}</h3>

            <input
              ref={input}
              type="file"
              accept="image/jpeg,image/png,image/heic,image/heif"
              onChange={onPick(side)}
              aria-label={`Choose the ${side} of your Aadhaar card`}
            />

            {checking === side && <p role="status">Checking the photo…</p>}

            {chosen && (
              <div>
                <img src={chosen.preview} alt={`Selected ${side}`} width={180} />

                {/* ⛔ The employee-facing text. CONTRACTS.md §1: the word
                    "fake" must never appear. A genuine card photographed
                    badly is indistinguishable from a forgery to any
                    automated check, which is exactly why no automated check
                    may call it one. */}
                {chosen.precheck.readable ? (
                  <p role="status">✓ The code on this photo is readable.</p>
                ) : (
                  <p role="status">
                    {chosen.quality.usable
                      ? precheckMessage(chosen.precheck)
                      : chosen.quality.guidance}
                  </p>
                )}

                <button type="button" onClick={() => input.current?.click()}>
                  Choose a different photo
                </button>
              </div>
            )}
          </section>
        );
      })}

      {error && <p role="alert">{error}</p>}

      <button type="button" disabled={!ready || busy} onClick={submit}>
        {busy ? 'Uploading…' : 'Submit'}
      </button>

      {ready && !(front?.precheck.readable && back?.precheck.readable) && (
        <p>
          You can still submit — we will try harder to read the code on our
          servers. Choosing a clearer photo usually gets an answer faster.
        </p>
      )}
    </div>
  );
}
