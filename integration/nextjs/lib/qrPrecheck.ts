/**
 * In-browser Secure QR pre-check — Step 11.
 *
 * ⛔ THIS IS THE ACTUAL FIX FOR THE DECODE RATE.
 *
 * The real corpus decoded at 22.7%. Step 7.5 made the server five times faster
 * and every preprocessing strategy actually run, and the rate did not move —
 * because the failures were not a processing problem. They were a capture
 * problem: photos too small, too far away, or compressed by a chat app before
 * anyone uploaded them.
 *
 * No amount of server work recovers information that is not in the file. The
 * only place that can be fixed is where the picture is taken.
 *
 * So: decode the QR in the BROWSER, before uploading. If the browser can read
 * it, the server will too. If it cannot, say so in about 50ms while the camera
 * is still open, instead of after an 8-second round trip that ends in "please
 * try again".
 *
 * ⛔ THIS IS A PRE-CHECK, NEVER A VERDICT.
 *
 *    The browser decodes only to answer "is this picture good enough to send?"
 *    It does NOT verify the signature, and its result never approves anything.
 *    Verification is an RSA check against UIDAI's public key on the server, and
 *    that is the only thing that can produce VERIFIED — CONTRACTS.md §1 Rule 1.
 *
 *    This is the same boundary the AI layer respects (CONTRACTS.md §7): things
 *    that improve INPUT may be fast, approximate and client-side; the thing
 *    that decides authenticity may not.
 *
 * ⛔ THE DECODED PAYLOAD NEVER LEAVES THE DEVICE.
 *
 *    It is a person's signed demographic record. We look at its length and
 *    shape to judge readability, then drop it. Only the image is uploaded, and
 *    the server decodes it again itself.
 */

/** Minimum digits for an Aadhaar Secure QR. Matches MIN_SECURE_QR_DIGITS server-side. */
export const MIN_SECURE_QR_DIGITS = 500;

export type PrecheckOutcome =
  | 'SECURE_QR_READABLE'
  | 'WRONG_QR_ON_THIS_FACE'
  | 'NO_QR_FOUND'
  | 'DETECTOR_UNAVAILABLE';

export interface PrecheckResult {
  readonly outcome: PrecheckOutcome;
  /** True only when a Secure QR was read. The gate for enabling upload. */
  readonly readable: boolean;
  /** Length of the payload. A COUNT — the content itself is discarded. */
  readonly payloadLength?: number;
  /** Bounding box short side, for the "move closer" guidance. */
  readonly qrPixels?: number;
  readonly detector: 'BarcodeDetector' | 'zxing-wasm' | 'none';
  readonly elapsedMs: number;
}

/**
 * Is this an Aadhaar Secure QR, as opposed to some other QR?
 *
 * The Secure QR is one enormous decimal integer — a big number encoding the
 * compressed, signed payload. A URL sticker, an app QR, or the short non-Secure
 * code some card faces carry will not match, and telling those apart matters:
 * "this side has no signed code, try the other side" is useful, while "no QR
 * found" when the person is clearly pointing at a QR is baffling.
 */
export function isSecureQrPayload(text: string): boolean {
  const trimmed = text.trim();
  return trimmed.length >= MIN_SECURE_QR_DIGITS && /^\d+$/.test(trimmed);
}

interface DetectedCode {
  readonly rawValue: string;
  readonly boundingBox?: { readonly width: number; readonly height: number };
}

/**
 * Decode any QR in a frame, preferring the browser's native detector.
 *
 * `BarcodeDetector` is hardware-accelerated on Android and Chrome desktop and
 * handles a dense Aadhaar QR in a few milliseconds — fast enough to run on live
 * video frames. Safari and Firefox do not implement it, hence the WASM
 * fallback, which is slower and therefore used on captured stills rather than
 * on every frame.
 */
export async function detectCodes(
  source: ImageBitmapSource,
): Promise<{ codes: DetectedCode[]; detector: PrecheckResult['detector'] }> {
  const native = (globalThis as { BarcodeDetector?: new (o?: object) => {
    detect(s: ImageBitmapSource): Promise<DetectedCode[]>;
  } }).BarcodeDetector;

  if (native) {
    try {
      const detector = new native({ formats: ['qr_code'] });
      return { codes: await detector.detect(source), detector: 'BarcodeDetector' };
    } catch {
      // Falls through. Some builds expose the constructor but throw on unsupported
      // formats, so a successful construction is not proof it works.
    }
  }

  const fallback = await loadWasmDecoder();
  if (fallback) {
    return { codes: await fallback(source), detector: 'zxing-wasm' };
  }
  return { codes: [], detector: 'none' };
}

/** The slice of the zxing-wasm reader API this file depends on. */
interface ZxingPoint {
  readonly x: number;
  readonly y: number;
}

interface ZxingResult {
  readonly text: string;
  readonly position?: {
    readonly topLeft: ZxingPoint;
    readonly topRight: ZxingPoint;
    readonly bottomLeft: ZxingPoint;
  };
}

interface ZxingReaderModule {
  readBarcodes(
    image: ImageData,
    options: { formats: string[]; tryHarder: boolean },
  ): Promise<ZxingResult[]>;
}

type WasmDecoder = (source: ImageBitmapSource) => Promise<DetectedCode[]>;
let wasmDecoder: WasmDecoder | null | undefined;

/**
 * Load `zxing-wasm` on demand.
 *
 * Deliberately lazy: it is roughly a megabyte, and a Chrome user with a native
 * detector should never pay for it. Cached — including the failure — so a
 * browser that cannot load it does not retry on every frame.
 */
async function loadWasmDecoder(): Promise<WasmDecoder | null> {
  if (wasmDecoder !== undefined) return wasmDecoder;

  try {
    // ⚠ Typed locally rather than imported. `zxing-wasm` is an OPTIONAL peer
    //   dependency — Chrome and Android never load it — so a hard import would
    //   break `tsc` for anyone who has not installed a package they do not
    //   need. The shape below is the part of its API we actually use, so a
    //   breaking change upstream surfaces as a type error rather than at
    //   runtime in a browser we cannot reproduce.
    // The specifier is held in a variable so TypeScript does not try to
    // resolve it at compile time. An optional dependency that is not installed
    // must not break `tsc` for the majority who never load it.
    const specifier = 'zxing-wasm/reader';
    const mod = (await import(/* @vite-ignore */ specifier)) as ZxingReaderModule;

    wasmDecoder = async (source: ImageBitmapSource) => {
      const bitmap = await createImageBitmap(source as ImageBitmapSource);
      const canvas = new OffscreenCanvas(bitmap.width, bitmap.height);
      const context = canvas.getContext('2d')!;
      context.drawImage(bitmap, 0, 0);
      const data = context.getImageData(0, 0, bitmap.width, bitmap.height);

      const results = await mod.readBarcodes(data, {
        formats: ['QRCode'],
        tryHarder: true,
      });
      return results.map((r: ZxingResult) => ({
        rawValue: r.text,
        boundingBox: r.position
          ? {
              width: Math.abs(r.position.topRight.x - r.position.topLeft.x),
              height: Math.abs(r.position.bottomLeft.y - r.position.topLeft.y),
            }
          : undefined,
      }));
    };
  } catch {
    wasmDecoder = null;
  }
  return wasmDecoder;
}

/**
 * Run the pre-check on one frame.
 *
 * ⚠ Returns quickly enough to run on live video (~50ms with the native
 *   detector), which is what makes "move closer" feel responsive rather than
 *   like a verdict delivered after the fact.
 */
export async function precheck(source: ImageBitmapSource): Promise<PrecheckResult> {
  const started = performance.now();
  const { codes, detector } = await detectCodes(source);
  const elapsedMs = Math.round(performance.now() - started);

  if (detector === 'none') {
    // ⚠ Not a failure of the photo. Upload must still be allowed — refusing
    //   because OUR pre-check is unavailable would lock out Safari users
    //   entirely. The server decodes anyway; this was only ever an accelerator.
    return { outcome: 'DETECTOR_UNAVAILABLE', readable: false, detector, elapsedMs };
  }

  const secure = codes.find((c) => isSecureQrPayload(c.rawValue));
  if (secure) {
    const box = secure.boundingBox;
    return {
      outcome: 'SECURE_QR_READABLE',
      readable: true,
      // A length, never the payload. The signed record stays on the device.
      payloadLength: secure.rawValue.trim().length,
      qrPixels: box ? Math.round(Math.min(box.width, box.height)) : undefined,
      detector,
      elapsedMs,
    };
  }

  const first = codes[0];
  if (first) {
    // A QR, but not the signed one — very likely the other face of the card.
    const box = first.boundingBox;
    return {
      outcome: 'WRONG_QR_ON_THIS_FACE',
      readable: false,
      qrPixels: box ? Math.round(Math.min(box.width, box.height)) : undefined,
      detector,
      elapsedMs,
    };
  }

  return { outcome: 'NO_QR_FOUND', readable: false, detector, elapsedMs };
}

/**
 * Plain-language guidance for a pre-check outcome.
 *
 * ⛔ Employee-facing. The word "fake" must never appear — CONTRACTS.md §1.
 *    Nothing here accuses anyone of anything; it describes what the camera
 *    should do differently.
 */
export function precheckMessage(result: PrecheckResult): string {
  switch (result.outcome) {
    case 'SECURE_QR_READABLE':
      return 'Code read successfully.';
    case 'WRONG_QR_ON_THIS_FACE':
      return 'That code is not the signed one — try the other side of the card.';
    case 'NO_QR_FOUND':
      return 'Point the camera at the side of the card with the square code.';
    case 'DETECTOR_UNAVAILABLE':
      return 'We will check your photo after upload.';
  }
}
