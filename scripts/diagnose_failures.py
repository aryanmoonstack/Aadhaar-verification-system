#!/usr/bin/env python3
"""Why did a well-formed capture fail to decode? — Step 14 diagnostic.

    python scripts/diagnose_failures.py C:\\aadhaar-corpus\\phone-b-good-light

⛔ THE QUESTION THIS ANSWERS

   Four images in the corpus are big, sharp and well-lit — px/module 24-29,
   sharpness 384-1063 — and still fail. A quality model built on those numbers
   would pass all four as "good" and they would still fail, which is the worst
   error it could make: confidently telling someone their photo is fine when it
   is not.

   Before any threshold ships, the cause has to be known rather than guessed.

⚠ THE HYPOTHESIS BEING TESTED — NOT ASSUMED

   D136 established that `find_qr_region` hallucinates: it reported a QR in 16
   of 19 images that contain none, the largest at 27.62 px/module. So a reading
   of "26.31 px/module" may not describe the real Aadhaar QR at all — it may
   describe a phantom, in which case the metric is meaningless for that image
   and the real code is somewhere else entirely, possibly tiny.

   This script settles it WITHOUT anyone having to look at a card:

     1. Crop to the region the localiser reported.
     2. Try to decode that crop ON ITS OWN.
     3. Try again upscaled 2x and 4x.

   If the crop decodes, the region was real and the problem is elsewhere.
   If the crop contains no QR at any scale, the region was a phantom — and
   every px_per_module figure for that image is fiction.

⚠ WHAT LEAVES YOUR MACHINE

   Nothing. Crops are written locally only if you pass `--save-crops`, into a
   folder that `.gitignore` already excludes. The console output is booleans,
   sizes and positions.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

_SIGNATURES: tuple[bytes, ...] = (
    b"\xff\xd8\xff",
    b"\x89PNG\r\n\x1a\n",
    b"BM",
    b"II*\x00",
    b"MM\x00*",
)


def looks_like_an_image(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            header = handle.read(16)
    except OSError:
        return False
    if any(header.startswith(signature) for signature in _SIGNATURES):
        return True
    return len(header) >= 12 and header[4:8] == b"ftyp"


def _variant(image, strategy: str):
    """Wrap a raw array as an ImageVariant so the cascade will accept it."""
    from avs.contracts import ImageVariant
    from avs.imaging.ops import encode_png

    return ImageVariant(data=encode_png(image), strategy=strategy, rotation=0)


def _compare(path, image, crop_decoded: bool) -> None:
    """Run the real generator + cascade and report how it differs from the crop."""
    import cv2

    from avs.imaging import PreprocessingVariantGenerator
    from avs.ingest import ImageIngestor
    from avs.qr import QrDecoderCascade

    try:
        validated = ImageIngestor().ingest(path.read_bytes())
    except BaseException as exc:
        print(f"      pipeline: ingest failed ({type(exc).__name__})")
        return

    variants = list(PreprocessingVariantGenerator().generate(validated))
    result = QrDecoderCascade(time_budget_seconds=6.0).decode(iter(variants))

    first = variants[0] if variants else None
    shape = ""
    if first is not None:
        import numpy as np

        decoded_first = cv2.imdecode(np.frombuffer(first.data, np.uint8), cv2.IMREAD_GRAYSCALE)
        if decoded_first is not None:
            shape = f"{decoded_first.shape[1]}x{decoded_first.shape[0]}"

    print(
        f"      pipeline: decoded={result.success}  variants={len(variants)}  "
        f"tried={result.attempts}  variant1={first.strategy if first else '-'} {shape}"
    )
    if crop_decoded and not result.success:
        print("      ⛔ THE CROP DECODES AND THE PIPELINE DOES NOT.")
        print("         A decode is being left on the table by preprocessing.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path, help="Folder of images to diagnose")
    parser.add_argument(
        "--compare-pipeline",
        action="store_true",
        help="Also run the REAL generator+cascade and report where it differs.",
    )
    parser.add_argument(
        "--save-crops",
        action="store_true",
        help="Write the located regions to <folder>/_crops/ so you can look at them.",
    )
    arguments = parser.parse_args()

    # ⛔ Placeholder first — "Not a directory" is technically true and useless
    #    when the argument was never a path to begin with.
    text = str(arguments.folder)
    if any(token in text for token in ("path\\to", "path/to", "<", ">", "your-")):
        print(f"⛔ That is the example path, not a real one: {text}\n")
        print("   Point at the FOLDER holding the images, e.g.")
        print("     python scripts/diagnose_failures.py C:\\aadhaar-corpus\\phone-a-dim")
        return 2

    if arguments.folder.is_file():
        # A single file is a reasonable thing to pass; use its folder and it
        # will be picked up along with its siblings.
        print(f"⛔ That is a file, not a folder: {arguments.folder.name}\n")
        print("   Point at the folder containing it:")
        print(f"     python scripts/diagnose_failures.py {arguments.folder.parent}")
        return 2

    if not arguments.folder.is_dir():
        print(f"⛔ No such folder: {arguments.folder}")
        return 2

    import cv2
    import numpy as np

    from avs.imaging.ops import find_qr_region, to_grayscale

    files = [
        p for p in sorted(arguments.folder.rglob("*")) if p.is_file() and looks_like_an_image(p)
    ]
    if not files:
        print(f"No images found under {arguments.folder}.")
        return 1

    crop_dir = arguments.folder / "_crops"
    if arguments.save_crops:
        crop_dir.mkdir(exist_ok=True)

    # ⛔ THE PROJECT'S OWN CASCADE, NOT cv2.QRCodeDetector.
    #
    #    The first version of this script judged crops with
    #    `cv2.QRCodeDetector`. `find_qr_region`'s own docstring says that
    #    detector "cannot locate a dense Secure QR — it fails even on a pristine
    #    synthetic one", which is precisely why the finder-pattern search exists.
    #
    #    So "the crop decodes at NO scale" may have been measuring cv2's
    #    weakness rather than the crop's. zxing-cpp — the decoder that actually
    #    reads the corpus — was never asked. That made the diagnostic's central
    #    verdict unreliable, on the one question it exists to answer.
    from avs.qr import QrDecoderCascade
    from avs.qr.cascade import classify_payload

    cascade = QrDecoderCascade(time_budget_seconds=4.0)
    print(f"Diagnosing {len(files)} image(s) with the real decoder cascade.\n")

    phantom = 0
    real = 0

    for path in files:
        image = cv2.imdecode(np.fromfile(path, dtype=np.uint8), cv2.IMREAD_COLOR)
        if image is None:
            continue

        height, width = image.shape[:2]
        grey = to_grayscale(image)
        region = find_qr_region(grey)

        print(f"{path.name}   ({width}x{height})")

        if region is None:
            print("    no region located at all\n")
            continue

        x, y, qr_w, qr_h = region
        # ⚠ Position as a FRACTION of the frame. An Aadhaar QR sits on one side
        #   of the card; a region dead-centre or spanning most of the frame is
        #   suspicious on its face.
        print(
            f"    located at ({x / width:.0%}, {y / height:.0%}) of frame, "
            f"size {qr_w}x{qr_h}px = {qr_w / 97:.1f} px/module"
        )

        # ⛔ THE TEST. Decode the crop alone, then upscaled. A real QR that is
        #    big and sharp should decode from its own crop trivially.
        # ⛔ 50%, NOT 10% — measured.
        #
        #    The finder-pattern box spans the pattern CENTRES, so it is always
        #    smaller than the code itself. On a known-good 700x700 QR the
        #    localiser reported 512x581 — 172px short on the left, 102px on the
        #    bottom. Cropping to that box plus 10% still cut modules off::
        #
        #        pad 10% -> FAIL      pad 25% -> FAIL      pad 50% -> DECODES
        #
        #    An earlier version used 10% and reported "phantom" for a region
        #    that was perfectly real, merely under-covered. Production is
        #    unaffected: Step 7.5's generator already pads 60% (`qr_context`).
        pad = int(0.50 * max(qr_w, qr_h))
        crop = grey[
            max(0, y - pad) : min(height, y + qr_h + pad),
            max(0, x - pad) : min(width, x + qr_w + pad),
        ]

        decoded_at = None
        secure = False
        for scale in (1, 2, 4):
            candidate = crop
            if scale > 1:
                candidate = cv2.resize(
                    crop, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC
                )
            try:
                result = cascade.decode(iter([_variant(candidate, f"crop-{scale}x")]))
            except BaseException:  # noqa: S112 — a failed scale is not an error
                continue
            if result.success and result.raw_payload:
                decoded_at = scale
                # ⛔ Boolean out. The payload is a real person's signed record
                #    and goes no further than this line.
                secure = classify_payload(result.raw_payload).value == "secure_qr"
                break

        if decoded_at:
            real += 1
            # ⛔ Length only. The payload is a real person's signed record and
            #    goes no further than the variable above.
            kind = "Secure QR" if secure else "a QR, but not an Aadhaar Secure QR"
            print(f"    ✓ THE CROP DECODES at {decoded_at}x — {kind}.")
            print("      So the code is readable in isolation but not in the full frame.")
        else:
            phantom += 1
            print("    ✗ the crop decodes at NO scale.")
            print("      Either a phantom region, or a genuinely unreadable code.")

        # ⛔ THE COMPARISON THAT MATTERS.
        #
        #    A crop decoding while the FULL pipeline fails means the pipeline is
        #    leaving a decode on the table. Two hypotheses for why were tested
        #    and both were WRONG:
        #
        #      "downscaling to target_qr_edge=520 destroys it"  -> no; a clean
        #         1900px QR still decodes after downscaling to 520
        #      "locating at scout_edge=1400 finds a worse region" -> no; scout
        #         and full-resolution boxes agree to within 1%
        #
        #    So rather than guess a third time, this prints what the generator
        #    ACTUALLY produced next to what the crop produced, and lets the
        #    difference show itself.
        if arguments.compare_pipeline:
            _compare(path, image, decoded_at is not None)

        if arguments.save_crops:
            out = crop_dir / f"{path.stem}_crop.png"
            cv2.imwrite(str(out), crop)
            print(f"      saved {out.name} — open it and see if that is your QR")

        print()

    print("=" * 70)
    print(f"Crop decoded: {real}    Crop did not decode: {phantom}")
    print("=" * 70)
    if real:
        print("★ Regions that decode ONLY when cropped mean the localiser is right")
        print("  and the DECODER is being defeated by the surrounding image —")
        print("  which is exactly what Step 15 (crop to the QR first) fixes.")
    if phantom:
        print("★ Regions that never decode mean px_per_module is unreliable for")
        print("  those images, and any threshold built on it is built on sand.")
        print("  Run again with --save-crops and look at one.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
