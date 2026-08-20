'use client';

/**
 * Aadhaar UPLOAD — file picker, not a camera. Images or PDF.
 *
 * ⛔ WHY THIS EXISTS ALONGSIDE `AadhaarCapture.tsx`
 *
 *    Step 11 shipped a live-camera component. M-One HRM offers file upload, not
 *    in-app capture, so that component does not fit the product: it opens
 *    `getUserMedia` and has no file input at all.
 *
 *    The valuable part of Step 11 was never the camera. `precheck()` accepts an
 *    `ImageBitmapSource`, and `File` extends `Blob`, so it runs on a picked file
 *    unchanged. Both libraries are reused here verbatim — only the shell differs.
 *
 * ⛔ THE BROWSER NEVER HOLDS THE SIGNING SECRET.
 *
 *    Calling AVS requires an HMAC signature, and anything shipped to a browser
 *    is public however it is obfuscated. Files go to `/api/aadhaar/verify` —
 *    a Next.js ROUTE HANDLER, which is server-side Node code owned by this same
 *    app. That route signs and forwards. No separate backend is involved, and
 *    no secret reaches this file.
 *
 * ⛔ TWO IMAGES, OR ONE PDF — CONTRACTS.md §11.
 *
 *    The UIDAI signature covers the QR payload only, never the printed card
 *    face. A genuine back paired with a forged front would otherwise sail
 *    through: the signature really does verify, because it says nothing about
 *    the face beside it.
 *
 *    That attack needs the two faces to come from DIFFERENT sources. Two
 *    photographs can; the pages of one PDF cannot. So a PDF is accepted alone
 *    and images are not.
 *
 *    And the QR may be on EITHER side — card formats vary, so a UI demanding
 *    "the QR is on the back" would turn away genuine cards.
 *
 * ★ WHY A PDF SKIPS THE PRE-CHECK INSTEAD OF FAILING IT
 *
 *   `createImageBitmap` cannot decode a PDF; it throws. Left alone, the catch
 *   branch would tell someone who uploaded a perfectly good e-Aadhaar that we
 *   "could not check this photo" — implying a problem with a file that is in
 *   fact the BEST input we accept.
 *
 *   A PDF holds the Secure QR as vector data. Rendered server-side at 300 DPI it
 *   has no blur, glare or JPEG ringing — none of the defects that held the
 *   measured photo corpus to a 30% decode rate. So the honest message is "we
 *   will read this on our servers", not a warning.
 */

import { useCallback, useRef, useState, type ChangeEvent } from 'react';

import { assess, looksCompressed, type QualityAssessment } from '../lib/captureQuality';
import { hasExif } from '../lib/exif';
import { precheck, precheckMessage, type PrecheckResult } from '../lib/qrPrecheck';

type Slot = 'front' | 'back';

interface ChosenFile {
  readonly file: File;
  readonly isPdf: boolean;
  /** Object URL for images. Null for a PDF — there is nothing to show. */
  readonly preview: string | null;
  readonly quality: QualityAssessment;
  readonly precheck: PrecheckResult;
}

/**
 * Content decides, not the filename.
 *
 * ⚠ `file.type` comes from the extension, which the user controls. Reading the
 *   first five bytes costs nothing and matches how the server decides. It only
 *   governs the UI here — AVS re-detects from magic bytes regardless.
 */
async function isPdf(file: File): Promise<boolean> {
  try {
    const head = await file.slice(0, 5).arrayBuffer();
    return new TextDecoder('latin1').decode(head) === '%PDF-';
  } catch {
    return file.type === 'application/pdf';
  }
}

const PDF_ACCEPTED: QualityAssessment = {
  usable: true,
  issues: [],
  guidance: 'PDF selected. We will read the code from it on our servers.',
  megapixels: 0,
};

const PDF_PRECHECK: PrecheckResult = {
  outcome: 'DETECTOR_UNAVAILABLE',
  readable: false,
  detector: 'none',
  elapsedMs: 0,
};

export interface Decision {
  readonly status_code: number;
  readonly status: 'APPROVED' | 'RETRY' | 'REVIEW';
  readonly message: string;
  readonly needs_review: boolean;
  readonly verdict: string;
  readonly signature_valid: boolean;
}

export interface AadhaarUploadProps {
  /** The server route that signs and forwards. ⛔ Never an AVS URL. */
  readonly uploadUrl?: string;
  readonly onSubmitted?: (jobId: string) => void;
  /** Called once the job settles, with the decision the server computed. */
  readonly onDecided?: (decision: Decision) => void;
}

export function AadhaarUpload({
  uploadUrl = '/api/aadhaar/verify',
  onSubmitted,
  onDecided,
}: AadhaarUploadProps) {
  const [front, setFront] = useState<ChosenFile | null>(null);
  const [back, setBack] = useState<ChosenFile | null>(null);
  const [password, setPassword] = useState('');
  const [passwordPrompt, setPasswordPrompt] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [checking, setChecking] = useState<Slot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [decision, setDecision] = useState<Decision | null>(null);

  const frontInput = useRef<HTMLInputElement>(null);
  const backInput = useRef<HTMLInputElement>(null);

  const inspect = useCallback(async (slot: Slot, file: File) => {
    setChecking(slot);
    setError(null);
    const set = slot === 'front' ? setFront : setBack;

    try {
      // ★ A PDF is not an image and must not be run through an image pre-check.
      //   Skipping is the correct outcome, not a degraded one.
      if (await isPdf(file)) {
        set({
          file,
          isPdf: true,
          preview: null,
          quality: PDF_ACCEPTED,
          precheck: PDF_PRECHECK,
        });
        return;
      }

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

      set({
        file,
        isPdf: false,
        preview: URL.createObjectURL(file),
        quality,
        precheck: result,
      });
    } catch {
      // ⛔ A pre-check failure must never block the upload. The server decodes
      //    anyway; this was only ever an accelerator. Refusing here because OUR
      //    check broke would turn a working submission into a dead end.
      set({
        file,
        isPdf: false,
        preview: URL.createObjectURL(file),
        quality: {
          usable: true,
          issues: [],
          guidance: 'We could not check this file here — you can still upload it.',
          megapixels: 0,
        },
        precheck: PDF_PRECHECK,
      });
    } finally {
      setChecking(null);
    }
  }, []);

  const onPick = useCallback(
    (slot: Slot) => (event: ChangeEvent<HTMLInputElement>) => {
      const file = event.target.files?.[0];
      if (file) void inspect(slot, file);
    },
    [inspect],
  );

  // A PDF already carries both faces, so the second slot disappears entirely
  // rather than sitting there implying something is missing.
  const pdfMode = front?.isPdf === true;

  const submit = useCallback(async () => {
    if (!front) return;
    setBusy(true);
    setError(null);
    setDecision(null);
    try {
      const form = new FormData();
      form.append('front', front.file, front.file.name || 'front.jpg');
      if (!pdfMode && back) {
        form.append('back', back.file, back.file.name || 'back.jpg');
      }
      // ⛔ Sent only when the employee actually typed one. Otherwise the server
      //    derives it from their profile — see lib/aadhaarPdfPassword.ts. Never
      //    written to localStorage, a cookie, or a log.
      if (pdfMode && password) {
        form.append('password', password);
      }

      const response = await fetch(uploadUrl, { method: 'POST', body: form });
      const body = await response.json();

      if (!response.ok || !body.jobId) {
        // The server route already phrases its errors for an employee.
        setError(typeof body.error === 'string' ? body.error : 'Upload failed. Please try again.');
        return;
      }

      onSubmitted?.(body.jobId);

      // ⚠ Poll here rather than leaving it to the parent, because the password
      //   box lives in this component: only the poll knows whether the file was
      //   locked, and only this component can show the field.
      for (let attempt = 0; attempt < 120; attempt++) {
        const poll = await fetch(`${uploadUrl}/${encodeURIComponent(body.jobId)}`, {
          cache: 'no-store',
        });
        const status = await poll.json();

        if (status.needsPassword) {
          // ⛔ Not an error state. The document may be perfectly good — we just
          //    do not have the key. Showing this in the error slot would tell
          //    someone their Aadhaar failed when it has not been read yet.
          setPasswordPrompt(status.passwordPrompt ?? 'Please enter the password for this PDF.');
          return;
        }

        if (status.decision) {
          setPasswordPrompt(null);
          setPassword('');
          setDecision(status.decision);
          onDecided?.(status.decision);
          return;
        }

        await new Promise((resolve) => setTimeout(resolve, 1000));
      }

      setError('This is taking longer than expected. Please try again.');
    } catch {
      setError('Upload failed. Please check your connection and try again.');
    } finally {
      setBusy(false);
    }
  }, [front, back, pdfMode, password, uploadUrl, onSubmitted, onDecided]);

  // ⛔ UPLOAD IS NEVER BLOCKED BY THE PRE-CHECK — only advised.
  //
  //    A photo the browser cannot read may still decode on the server, which
  //    runs 23 preprocessing variants the browser does not. On Safari the
  //    detector is simply absent. Disabling the button on a failed pre-check
  //    would lock those people out of the product entirely.
  //
  //    What IS enforced is §11: one PDF, or two images.
  const ready = pdfMode ? front !== null : front !== null && back !== null;

  const slots: readonly Slot[] = pdfMode ? (['front'] as const) : (['front', 'back'] as const);

  return (
    <div>
      <h2>Upload your Aadhaar</h2>
      <p>
        Upload your Aadhaar PDF on its own, or photos of both sides. Whichever
        side has the QR code, we will find it.
      </p>

      {slots.map((slot) => {
        const chosen = slot === 'front' ? front : back;
        const input = slot === 'front' ? frontInput : backInput;
        const heading = pdfMode ? 'Aadhaar PDF' : slot === 'front' ? 'Front' : 'Back';

        return (
          <section key={slot} aria-labelledby={`${slot}-heading`}>
            <h3 id={`${slot}-heading`}>{heading}</h3>

            <input
              ref={input}
              type="file"
              accept={
                slot === 'front'
                  ? 'image/jpeg,image/png,image/heic,image/heif,application/pdf'
                  : 'image/jpeg,image/png,image/heic,image/heif'
              }
              onChange={onPick(slot)}
              aria-label={
                slot === 'front'
                  ? 'Choose your Aadhaar PDF, or the front of your card'
                  : 'Choose the back of your Aadhaar card'
              }
            />

            {checking === slot && <p role="status">Checking the file…</p>}

            {chosen && (
              <div>
                {chosen.preview ? (
                  <img src={chosen.preview} alt={`Selected ${slot}`} width={180} />
                ) : (
                  <p>{chosen.file.name}</p>
                )}

                {/* ⛔ The employee-facing text. CONTRACTS.md §1: the word
                    "fake" must never appear. A genuine card photographed
                    badly is indistinguishable from a forgery to any
                    automated check, which is exactly why no automated check
                    may call it one. */}
                {chosen.isPdf ? (
                  <p role="status">{chosen.quality.guidance}</p>
                ) : chosen.precheck.readable ? (
                  <p role="status">✓ The code on this photo is readable.</p>
                ) : (
                  <p role="status">
                    {chosen.quality.usable
                      ? precheckMessage(chosen.precheck)
                      : chosen.quality.guidance}
                  </p>
                )}

                <button type="button" onClick={() => input.current?.click()}>
                  Choose a different file
                </button>
              </div>
            )}
          </section>
        );
      })}

      {/* ★ HIDDEN UNTIL IT IS ACTUALLY NEEDED.
          The server derives the password from the employee's profile — first 4
          letters of the name in capitals plus the birth year — so most people
          never see this box at all. It appears only when that derivation
          missed, which happens when the HRM's name differs from the one printed
          on the Aadhaar.

          ⛔ The prompt is a FIRST REQUEST, never "wrong password". At this
             point the employee has typed nothing; the guess was ours. */}
      {passwordPrompt && (
        <section aria-labelledby="password-heading">
          <h3 id="password-heading">PDF password</h3>
          <p>{passwordPrompt}</p>
          <input
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete="off"
            aria-label="Password for your Aadhaar PDF"
          />
          <button type="button" disabled={!password || busy} onClick={submit}>
            {busy ? 'Checking…' : 'Unlock and check'}
          </button>
        </section>
      )}

      {error && <p role="alert">{error}</p>}

      {/* ⛔ The service's own wording, verbatim. CONTRACTS.md §1 — it is phrased
          so it never accuses anyone of forgery, and the word "fake" must not
          appear in employee-facing text. Do not substitute your own copy. */}
      {decision && (
        <p role="status" data-status={decision.status}>
          {decision.message}
        </p>
      )}

      <button type="button" disabled={!ready || busy} onClick={submit}>
        {busy ? 'Checking…' : 'Submit'}
      </button>

      {ready && !pdfMode && !(front?.precheck.readable && back?.precheck.readable) && (
        <p>
          You can still submit — we will try harder to read the code on our
          servers. Choosing a clearer photo usually gets an answer faster.
        </p>
      )}
    </div>
  );
}
