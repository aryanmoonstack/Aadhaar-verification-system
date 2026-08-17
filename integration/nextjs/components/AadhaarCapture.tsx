'use client';

/**
 * Two-sided Aadhaar capture — Step 11.
 *
 * ⛔ BOTH FACES ARE REQUIRED — CONTRACTS.md §11.
 *
 *    The UIDAI signature covers the QR payload only, never the printed card
 *    face. A genuine back photographed alongside a forged front would otherwise
 *    sail through: the signature really does verify, because it says nothing
 *    about the face beside it.
 *
 *    The QR may be on EITHER side. Card formats vary, and a UI that demanded
 *    "the QR is on the back" would turn away a large share of genuine cards.
 *
 * ⛔ THE BROWSER NEVER TALKS TO AVS DIRECTLY.
 *
 *    Calling AVS requires an HMAC signature, and a browser cannot hold a
 *    signing secret — anything shipped to the client is public. Images go to
 *    the HRM, which signs server-side and forwards. A "helpful" refactor that
 *    lets the browser call AVS would put the tenant key in a JavaScript bundle.
 *
 * THE DESIGN PROBLEM THIS SOLVES
 * ------------------------------
 * The measured decode rate on real photos was 22.7%. Server-side work in Step
 * 7.5 made everything five times faster and moved that number not at all,
 * because the failures were captures that could never have worked: too far
 * away, or compressed by a chat app before upload.
 *
 * So the camera checks the code is readable BEFORE anything is sent. Feedback
 * arrives in ~50ms while the camera is open, rather than as a rejection eight
 * seconds later.
 */

import { useCallback, useEffect, useRef, useState } from 'react';

import { assess, type QualityAssessment } from '../lib/captureQuality';
import { precheck, precheckMessage, type PrecheckResult } from '../lib/qrPrecheck';

type Side = 'front' | 'back';

interface CapturedSide {
  readonly blob: Blob;
  readonly preview: string;
  readonly quality: QualityAssessment;
  readonly precheck: PrecheckResult;
}

export interface AadhaarCaptureProps {
  /** Where the HRM accepts the upload. Never an AVS URL. */
  readonly uploadUrl?: string;
  readonly onSubmitted?: (jobId: string) => void;
}

export function AadhaarCapture({
  uploadUrl = '/api/aadhaar/verify',
  onSubmitted,
}: AadhaarCaptureProps) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const streamRef = useRef<MediaStream | null>(null);

  const [side, setSide] = useState<Side>('front');
  const [captured, setCaptured] = useState<Partial<Record<Side, CapturedSide>>>({});
  const [liveHint, setLiveHint] = useState('Point the camera at your Aadhaar card.');
  const [busy, setBusy] = useState(false);
  const [cameraError, setCameraError] = useState<string | null>(null);

  // ── Camera ────────────────────────────────────────────────────────────────

  useEffect(() => {
    let cancelled = false;

    async function start() {
      try {
        const stream = await navigator.mediaDevices.getUserMedia({
          video: {
            // ⚠ Ask for the highest resolution available. Every 2.3MP image in
            //   the corpus failed; a default-resolution stream is often exactly
            //   that. `ideal` rather than `exact` so a modest camera still works.
            facingMode: { ideal: 'environment' },
            width: { ideal: 3840 },
            height: { ideal: 2160 },
          },
          audio: false,
        });
        if (cancelled) {
          stream.getTracks().forEach((t) => t.stop());
          return;
        }
        streamRef.current = stream;
        if (videoRef.current) {
          videoRef.current.srcObject = stream;
          await videoRef.current.play();
        }
      } catch {
        // Permission denied, no camera, or insecure origin. File upload still
        // works, so this is a downgrade rather than a dead end.
        setCameraError(
          'We could not open the camera. You can still choose a photo from your device.',
        );
      }
    }

    start();
    return () => {
      cancelled = true;
      streamRef.current?.getTracks().forEach((t) => t.stop());
    };
  }, []);

  // ── Live guidance ─────────────────────────────────────────────────────────

  useEffect(() => {
    if (cameraError) return;
    let active = true;

    // ⚠ Every 600ms, not every frame. The pre-check takes ~50ms natively but
    //   far longer under the WASM fallback, and running it continuously would
    //   drain the battery and make the preview stutter — which makes it harder
    //   to hold the camera steady, causing the very blur we are trying to avoid.
    const timer = setInterval(async () => {
      const video = videoRef.current;
      if (!active || !video || video.readyState < 2) return;

      try {
        const bitmap = await createImageBitmap(video);
        const result = await precheck(bitmap);
        bitmap.close();
        if (!active) return;

        setLiveHint(
          result.readable
            ? 'Code detected — hold still and capture.'
            : precheckMessage(result),
        );
      } catch {
        // A transient frame-grab failure is not worth surfacing.
      }
    }, 600);

    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [cameraError]);

  // ── Capture ───────────────────────────────────────────────────────────────

  const capture = useCallback(async () => {
    const video = videoRef.current;
    if (!video) return;

    setBusy(true);
    try {
      const canvas = document.createElement('canvas');
      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;
      canvas.getContext('2d')!.drawImage(video, 0, 0);

      // ⚠ Quality 0.95, not the 0.8 default. JPEG artefacts land exactly on the
      //   high-contrast edges that define QR modules, and a code that decodes at
      //   0.95 can fail at 0.8. The extra bytes are cheaper than a re-upload.
      const blob = await new Promise<Blob>((resolve) =>
        canvas.toBlob((b) => resolve(b!), 'image/jpeg', 0.95),
      );

      const result = await precheck(canvas);
      const quality = assess({
        width: canvas.width,
        height: canvas.height,
        qrPixels: result.qrPixels,
      });

      setCaptured((prev) => ({
        ...prev,
        [side]: { blob, preview: URL.createObjectURL(blob), quality, precheck: result },
      }));

      // Move to the other side automatically — one less thing to explain.
      setSide((current) => (current === 'front' ? 'back' : 'front'));
    } finally {
      setBusy(false);
    }
  }, [side]);

  // ── Submit ────────────────────────────────────────────────────────────────

  const front = captured.front;
  const back = captured.back;

  /**
   * ⛔ Requires BOTH faces, and at least one readable Secure QR.
   *
   * Requiring a readable code on a SPECIFIC side would be wrong — placement
   * varies by card format. Requiring one on EITHER side is the real constraint,
   * and checking it here means the person is not sent away eight seconds later.
   */
  const readyToSubmit =
    Boolean(front && back) &&
    (front!.precheck.readable ||
      back!.precheck.readable ||
      // If no detector is available we cannot know, so we must not block.
      front!.precheck.outcome === 'DETECTOR_UNAVAILABLE');

  const submit = useCallback(async () => {
    if (!front || !back) return;
    setBusy(true);
    try {
      const form = new FormData();
      form.append('front', front.blob, 'front.jpg');
      form.append('back', back.blob, 'back.jpg');

      // The HRM signs and forwards. The browser holds no secret.
      const response = await fetch(uploadUrl, { method: 'POST', body: form });
      const body = await response.json();

      if (response.ok && body.jobId) {
        onSubmitted?.(body.jobId);
      }
    } finally {
      setBusy(false);
    }
  }, [front, back, uploadUrl, onSubmitted]);

  // ── View ──────────────────────────────────────────────────────────────────

  return (
    <div className="aadhaar-capture">
      <h2>Verify your Aadhaar</h2>
      <p>
        We need a photo of <strong>both sides</strong> of your card. The square
        code can be on either side — we will find it.
      </p>

      {cameraError ? (
        <p role="status">{cameraError}</p>
      ) : (
        <>
          <video ref={videoRef} playsInline muted aria-label="Camera preview" />
          {/* aria-live so the guidance is announced, not just shown. Someone
              using a screen reader cannot see the preview at all. */}
          <p role="status" aria-live="polite">
            {liveHint}
          </p>
          <button type="button" onClick={capture} disabled={busy}>
            Capture {side === 'front' ? 'front' : 'back'}
          </button>
        </>
      )}

      <div className="captured">
        {(['front', 'back'] as const).map((which) => {
          const shot = captured[which];
          return (
            <figure key={which}>
              <figcaption>{which === 'front' ? 'Front' : 'Back'}</figcaption>
              {shot ? (
                <>
                  <img src={shot.preview} alt={`${which} of your Aadhaar card`} />
                  <p role="status">
                    {shot.precheck.readable
                      ? 'Code read successfully.'
                      : shot.quality.usable
                        ? precheckMessage(shot.precheck)
                        : shot.quality.guidance}
                  </p>
                </>
              ) : (
                <p>Not captured yet.</p>
              )}
            </figure>
          );
        })}
      </div>

      <button type="button" onClick={submit} disabled={!readyToSubmit || busy}>
        {busy ? 'Working…' : 'Submit for verification'}
      </button>

      {front && back && !readyToSubmit && (
        <p role="status">
          We could not read the square code on either photo. Please retake the
          side that has it, moving a little closer.
        </p>
      )}
    </div>
  );
}
