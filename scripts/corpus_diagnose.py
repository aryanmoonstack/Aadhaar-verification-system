#!/usr/bin/env python3
"""Find out WHY real photos fail to decode — runs locally only.

    python scripts/corpus_diagnose.py C:\\aadhaar-corpus --out diagnosis.txt

⛔ PRINTS NO PERSONAL DATA. Pixel dimensions, percentages, booleans and timings
   only. It never writes a payload, never parses fields, never touches a name or
   a number. Where it succeeds it reports only *that* it succeeded.

WHY THIS EXISTS
---------------
`corpus_report.py` measured 22.7% on real photos, and every success came from
the untouched image on the first attempt — all 23 preprocessing strategies
rescued nothing while costing ~15s per failure. Preprocessing cannot fix this,
so we need to know what actually went wrong.

THE QUESTION THAT DECIDES EVERYTHING
------------------------------------
How many PIXELS PER MODULE does the QR have?

The Aadhaar Secure QR carries ~2000 characters, which needs a version-20-plus
symbol — roughly 97 modules across. A decoder needs about 2 pixels per module to
resolve one, 3 to be comfortable. Below that the information is not in the file
and no filter, model or amount of cleverness can invent it.

    QR 400px wide  ->  4.1 px/module  ->  decodes
    QR 200px wide  ->  2.1 px/module  ->  marginal
    QR 130px wide  ->  1.3 px/module  ->  physically unrecoverable

If the failures are above ~2.0, they are a software problem and a localiser
fixes them. If they are below, it is a capture problem and only the upload UI
can fix it — by telling people to fill the frame. Those are completely
different projects, which is why this measurement comes first.

⚠ LESSON FROM THE FIRST VERSION OF THIS SCRIPT
   It used `cv2.QRCodeDetector`, wrapped in a bare `except: pass`. That detector
   fails on dense QRs — it cannot even locate a pristine synthetic one — so the
   script reported "QR not located" for all 22 images, INCLUDING five it had
   just decoded successfully, and presented that as data.

   Hence `self_test()` below. The tool proves it can find a QR it generated
   itself before it is allowed to report anything about yours.
"""

from __future__ import annotations

import argparse
import statistics
import sys
import time
from collections import Counter
from pathlib import Path
from typing import NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import cv2
import numpy as np

from avs.ingest.magic import FileKind, detect
from avs.qr.cascade import MIN_SECURE_QR_DIGITS, classify_payload

IMAGE_KINDS = frozenset({FileKind.JPEG, FileKind.PNG, FileKind.WEBP, FileKind.HEIF})

#: A version-20 QR is 97 modules across. Aadhaar payloads land at or above this,
#: so it is a slight over-estimate of px/module — erring towards optimism.
MODULES_ACROSS = 97


# --------------------------------------------------------------------------- #
# Decode — we only ever ask "did it decode, and was it a Secure QR?"
# --------------------------------------------------------------------------- #


class Decoded(NamedTuple):
    """What a decode attempt found. Never carries payload content.

    ★ `secure` and `any_qr` are separate on purpose. The first version returned
      a single bool, so "found nothing" and "found a QR that is not a Secure QR"
      were indistinguishable — and newer Aadhaar cards carry a small non-Secure
      QR on the front face. Merging those two hides the most likely explanation
      for a bad decode rate behind the least useful one.
    """

    secure: bool = False
    any_qr: bool = False
    length: int = 0
    digits_only: bool = False
    box: tuple[int, int, int, int] | None = None


def try_decode(image: np.ndarray) -> Decoded:
    """Decode and classify. The payload text never leaves this function —
    only its length and character class, which are counts, not content."""
    try:
        import zxingcpp
    except ImportError:
        return Decoded()

    try:
        results = zxingcpp.read_barcodes(image)
    except Exception:
        return Decoded()

    best = Decoded()
    for result in results or []:
        text = result.text or ""
        if not text:
            continue

        box = None
        try:
            p = result.position
            xs = [p.top_left.x, p.top_right.x, p.bottom_left.x, p.bottom_right.x]
            ys = [p.top_left.y, p.top_right.y, p.bottom_left.y, p.bottom_right.y]
            box = (min(xs), min(ys), max(xs) - min(xs), max(ys) - min(ys))
        except AttributeError:
            pass

        kind = classify_payload(text)
        secure = getattr(kind, "name", str(kind)).upper().startswith("SECURE") or (
            text.isdigit() and len(text) >= MIN_SECURE_QR_DIGITS
        )
        found = Decoded(secure, True, len(text), text.isdigit(), box)
        if secure:
            return found
        # Keep the longest non-Secure hit — it is the most informative.
        if found.length > best.length:
            best = found

    return best


# --------------------------------------------------------------------------- #
# Localisation — finder patterns, not cv2.QRCodeDetector
# --------------------------------------------------------------------------- #


def locate_qr(gray: np.ndarray, min_size: int = 6) -> tuple[int, int, int, int] | None:
    """Find a QR's bounding box WITHOUT decoding it.

    Every QR carries three finder patterns — three concentric squares in a
    1:1:3:1:1 ratio at three corners. Under `RETR_TREE` that shows up as a
    contour nested at least two deep and roughly square, which is a rare enough
    signature in a photograph to be a reliable marker.

    This matters because it works on QRs that are too small or too blurred to
    DECODE, which is exactly the population we are trying to measure. Validated
    against zxing's own reported corners in `self_test()` — agreement is within
    a few pixels.
    """
    best: tuple[int, int, int, int] | None = None

    for block in (31, 61, 101):
        try:
            threshold = cv2.adaptiveThreshold(
                gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, block, 5
            )
            contours, hierarchy = cv2.findContours(
                threshold, cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE
            )
        except cv2.error:
            continue
        if hierarchy is None:
            continue

        hierarchy = hierarchy[0]
        marks: list[tuple[int, int, int, int]] = []
        for index, contour in enumerate(contours):
            depth, parent = 0, hierarchy[index][3]
            while parent != -1 and depth < 6:
                depth += 1
                parent = hierarchy[parent][3]
            if depth < 2:
                continue
            x, y, w, h = cv2.boundingRect(contour)
            if w < min_size or h < min_size or not (0.6 < w / h < 1.6):
                continue
            if cv2.contourArea(contour) < 0.4 * w * h:
                continue
            marks.append((x, y, w, h))

        if len(marks) < 3:
            continue

        # Three finder patterns of one QR are near-identical in size. Scan
        # size-ordered triples and keep the largest plausible enclosing box.
        marks.sort(key=lambda m: m[2] * m[3])
        for i in range(len(marks) - 2):
            trio = marks[i : i + 3]
            sizes = [m[2] for m in trio]
            if max(sizes) > 2.2 * min(sizes):
                continue
            if not _is_finder_triangle(trio):
                # ★ Three similar squares are not enough. Real finder patterns
                #   sit at three corners of a square, so their centres form a
                #   RIGHT ISOCELES triangle. Without this check the detector
                #   happily merged unrelated card features into a box covering
                #   91% of the frame and reported it as a giant QR.
                continue
            xs = [m[0] for m in trio] + [m[0] + m[2] for m in trio]
            ys = [m[1] for m in trio] + [m[1] + m[3] for m in trio]
            box = (min(xs), min(ys), max(xs) - min(xs), max(ys) - min(ys))
            big_enough = box[2] > min_size * 3 and box[3] > min_size * 3
            if big_enough and (best is None or box[2] * box[3] > best[2] * best[3]):
                best = box

    return best


def _is_finder_triangle(trio: list[tuple[int, int, int, int]], tolerance: float = 0.30) -> bool:
    """Do these three marks sit at three corners of a square?"""
    centres = [(x + w / 2, y + h / 2) for x, y, w, h in trio]
    sides = sorted(
        ((centres[i][0] - centres[j][0]) ** 2 + (centres[i][1] - centres[j][1]) ** 2) ** 0.5
        for i, j in ((0, 1), (1, 2), (0, 2))
    )
    if sides[0] <= 0:
        return False
    # Two equal legs...
    if abs(sides[1] - sides[0]) / sides[0] > tolerance:
        return False
    # ...and a hypotenuse of leg * sqrt(2).
    expected = sides[0] * 2**0.5
    if abs(sides[2] - expected) / expected > tolerance:
        return False
    # The QR must be meaningfully bigger than one finder pattern.
    return sides[0] > trio[0][2] * 1.5


def crop(gray: np.ndarray, box: tuple[int, int, int, int], margin: float = 0.20) -> np.ndarray:
    x, y, w, h = box
    pad_x, pad_y = int(w * margin), int(h * margin)
    height, width = gray.shape[:2]
    return gray[
        max(0, y - pad_y) : min(height, y + h + pad_y),
        max(0, x - pad_x) : min(width, x + w + pad_x),
    ]


def scale_to(image: np.ndarray, target: int) -> np.ndarray:
    """Resize so the longest side is `target`. Scales UP or DOWN.

    The first version only ever scaled up, and only when the input was already
    smaller than the target — so a 1500px tile cut from a 12MP photo was left
    untouched and the whole tiled search did nothing.
    """
    height, width = image.shape[:2]
    longest = max(height, width)
    if longest == 0:
        return image
    factor = target / longest
    if 0.95 < factor < 1.05:
        return image
    interpolation = cv2.INTER_CUBIC if factor > 1 else cv2.INTER_AREA
    return cv2.resize(image, None, fx=factor, fy=factor, interpolation=interpolation)


# --------------------------------------------------------------------------- #


def self_test() -> tuple[bool, str]:
    """Prove the localiser works before trusting anything it says.

    Renders a QR, then requires both that zxing decodes it and that `locate_qr`
    finds it within a sane distance of zxing's own corners. A tool that reports
    "not found" 22 times because its detector is broken is worse than no tool.
    """
    try:
        from tests.fixtures.qr_images import encode_jpeg, render_card
        from tests.fixtures.synthetic import SyntheticQrBuilder, make_test_keypair
    except ImportError as exc:
        return False, f"cannot import test fixtures: {exc}"

    key, _ = make_test_keypair()
    data = encode_jpeg(render_card(SyntheticQrBuilder(private_key=key).build()))
    gray = cv2.cvtColor(
        cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR), cv2.COLOR_BGR2GRAY
    )

    found = try_decode(gray)
    truth = found.box
    if not found.secure:
        return False, "zxing could not decode a pristine synthetic QR — decoder is broken"

    found = locate_qr(gray)
    if found is None:
        return False, "localiser could not find a QR that zxing just decoded"

    if truth is not None:
        drift = max(abs(found[0] - truth[0]), abs(found[1] - truth[1]))
        tolerance = max(20, truth[2] * 0.15)
        if drift > tolerance:
            return False, f"localiser box is {drift}px from zxing's — too far to trust"
        return True, f"localiser agrees with zxing to within {drift}px"

    return True, "localiser found the QR"


def experiments(data: bytes) -> tuple[str | None, dict]:
    """Run the recovery ladder. Returns (first experiment that worked, facts)."""
    colour = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
    if colour is None:
        return None, {"unreadable": True}

    height, width = colour.shape[:2]
    gray = cv2.cvtColor(colour, cv2.COLOR_BGR2GRAY)

    facts: dict = {
        "megapixels": round(width * height / 1_000_000, 1),
        "blur": round(float(cv2.Laplacian(gray, cv2.CV_64F).var()), 1),
    }

    found = try_decode(gray)
    # ⚠ Only zxing's box is ground truth. `locate_qr` is an ESTIMATE, and on an
    #   image that does not decode there is nothing to check it against.
    box = found.box
    facts_box_source = "zxing" if box is not None else "estimated"
    if box is None:
        box = locate_qr(gray)

    facts["qr_located"] = box is not None
    facts["box_source"] = facts_box_source
    if box is not None:
        qr_px = min(box[2], box[3])
        facts["qr_px"] = qr_px
        facts["px_per_module"] = round(qr_px / MODULES_ACROSS, 2)
        facts["qr_frac"] = round(100.0 * (box[2] * box[3]) / (width * height), 2)

    if found.any_qr:
        facts["payload_len"] = found.length
        facts["digits_only"] = found.digits_only
    if found.secure:
        return "E0_original", facts
    if found.any_qr:
        # ★ A QR was read — it is simply not a Secure QR. Completely different
        #   problem from "no QR found", and a completely different fix.
        facts["wrong_qr"] = True

    if box is not None:
        region = crop(gray, box)
        for name, image in (
            ("E1_crop", region),
            ("E2_crop_upscale", scale_to(region, 900)),
            (
                "E3_crop_upscale_sharpen",
                cv2.filter2D(
                    scale_to(region, 900), -1, np.array([[0, -1, 0], [-1, 5, -1], [0, -1, 0]])
                ),
            ),
            (
                "E4_crop_upscale_threshold",
                cv2.adaptiveThreshold(
                    scale_to(region, 900),
                    255,
                    cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                    cv2.THRESH_BINARY,
                    31,
                    5,
                ),
            ),
            ("E5_crop_big_upscale", scale_to(region, 1600)),
        ):
            attempt = try_decode(image)
            if attempt.secure:
                facts["payload_len"] = attempt.length
                return name, facts
            if attempt.any_qr:
                facts["wrong_qr"] = True
                facts.setdefault("payload_len", attempt.length)

    # E6 — detector-free sliding window. Fixed 700px windows at 50% overlap,
    # each scaled to 1400. Independent of localisation, so it answers "is the
    # information there at all" even when nothing could be found.
    window = 700
    for y0 in range(0, max(1, height - window // 2), window // 2):
        for x0 in range(0, max(1, width - window // 2), window // 2):
            tile = gray[y0 : y0 + window, x0 : x0 + window]
            if tile.size == 0 or min(tile.shape[:2]) < 60:
                continue
            attempt = try_decode(scale_to(tile, 1400))
            if attempt.secure:
                facts["payload_len"] = attempt.length
                return "E6_sliding_window", facts
            if attempt.any_qr:
                facts["wrong_qr"] = True

    return None, facts


def deep_recover(gray: np.ndarray) -> str | None:
    """Exhaustive full-frame search. Does NOT depend on localisation.

    ★ Every earlier experiment ran on a crop chosen by `locate_qr`, and that
      function is only validated on images that already decode — where zxing
      supplies the true corners anyway. On a FAILING image its box is an
      unverified guess, so any conclusion drawn from it is circular.

      This routine removes the localiser from the loop entirely: a matrix of
      transforms over the whole frame at several scales. If none of ~40
      attempts finds a Secure QR, the image does not contain a readable one and
      no amount of further engineering will change that.

    Slow and deliberately brutal. It is a measurement, not the product.
    """
    height, width = gray.shape[:2]

    def variants(image: np.ndarray):
        yield "raw", image
        yield "clahe", cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8)).apply(image)
        yield "otsu", cv2.threshold(image, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1]
        for block in (31, 61, 121):
            yield (
                f"adaptive{block}",
                cv2.adaptiveThreshold(
                    image, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, block, 5
                ),
            )
        yield (
            "sharpen",
            cv2.filter2D(image, -1, np.array([[0, -1, 0], [-1, 5, -1], [0, -1, 0]])),
        )
        # Illumination flattening — the standard answer to glare and shadow.
        background = cv2.morphologyEx(
            image, cv2.MORPH_CLOSE, cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (51, 51))
        )
        yield "flatfield", cv2.divide(image, background, scale=255)
        yield "invert", cv2.bitwise_not(image)

    # Several scales: a QR can be too large for the decoder as well as too small.
    for target in (max(height, width), 3000, 2000, 1400, 1000):
        scaled = scale_to(gray, target)
        for name, image in variants(scaled):
            if try_decode(image).secure:
                return f"deep:{name}@{target}"
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Diagnose decode failures. No personal data.")
    parser.add_argument("corpus", type=Path)
    parser.add_argument("--out", type=Path, default=Path("diagnosis.txt"))
    parser.add_argument(
        "--deep",
        action="store_true",
        help="Exhaustive full-frame recovery on every failure. Slow (~30s/image) "
        "but independent of localisation, so its answer is trustworthy.",
    )
    args = parser.parse_args()

    ok, message = self_test()
    print(f"self-test : {'PASS' if ok else 'FAIL'}  ({message})")
    if not ok:
        print("\nRefusing to report. A broken detector produces zeros that look")
        print("like findings, which is worse than no measurement at all.")
        return 1

    files = [p for p in args.corpus.rglob("*") if p.is_file() and p.name != "README.txt"]
    images = []
    for path in files:
        try:
            with path.open("rb") as handle:
                if detect(handle.read(64)).kind in IMAGE_KINDS:
                    images.append(path)
        except OSError:
            continue
    images.sort()

    if not images:
        print(f"No images under {args.corpus}")
        return 1

    lines: list[str] = []

    def emit(text: str = "") -> None:
        print(text)
        lines.append(text)

    emit("=" * 70)
    emit("AVS decode diagnosis")
    emit("=" * 70)
    emit(f"self-test : PASS ({message})")
    emit("Pixel sizes, percentages and booleans only. Safe to share.")
    emit()

    winners: Counter = Counter()
    wrong_qr_count = 0
    per_image: list[tuple[str, dict, str | None]] = []
    module_sizes: list[float] = []
    qr_pixels: list[int] = []
    megapixels: list[float] = []
    located = 0

    for index, path in enumerate(images, start=1):
        condition = path.parent.name
        print(f"  [{index}/{len(images)}] {condition} … ", end="", flush=True)
        started = time.perf_counter()
        data = path.read_bytes()
        winner, facts = experiments(data)
        if winner is None and args.deep:
            colour = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
            if colour is not None:
                winner = deep_recover(cv2.cvtColor(colour, cv2.COLOR_BGR2GRAY))
        elapsed = time.perf_counter() - started

        per_image.append((condition, facts, winner))
        megapixels.append(facts.get("megapixels", 0))
        if facts.get("qr_located"):
            located += 1
            qr_pixels.append(facts["qr_px"])
            module_sizes.append(facts["px_per_module"])

        if winner is None and facts.get("wrong_qr"):
            winners["WRONG_QR_ON_THIS_FACE"] += 1
            wrong_qr_count += 1
        else:
            winners[winner or "NO_QR_AT_ALL"] += 1
        qr_note = (
            f"QR {facts['qr_px']}px = {facts['px_per_module']}px/mod"
            if facts.get("qr_located")
            else "QR not located"
        )
        print(f"{winner or 'no decode':<26} {qr_note:<30} {elapsed:.1f}s")

    total = len(images)

    emit("-" * 70)
    emit("H1  IMAGE SIZE")
    emit("-" * 70)
    if megapixels:
        emit(
            f"  megapixels : min {min(megapixels)}  median "
            f"{statistics.median(megapixels)}  max {max(megapixels)}"
        )

    emit()
    emit("-" * 70)
    emit("H2  *** QR SIZE IN PIXELS — the number that decides everything ***")
    emit("-" * 70)
    ground_truth = sum(1 for _, f, _ in per_image if f.get("box_source") == "zxing")
    emit(f"  QR located in : {located}/{total} images")
    emit(f"    of which ground truth (from a successful decode) : {ground_truth}")
    emit(f"    of which UNVALIDATED estimates                   : {located - ground_truth}")
    emit("    ^ treat the estimates with suspicion: the localiser cannot be")
    emit("      checked on an image that does not decode.")
    if module_sizes:
        emit(
            f"  QR short side : min {min(qr_pixels)}px  median "
            f"{statistics.median(qr_pixels):.0f}px  max {max(qr_pixels)}px"
        )
        emit(
            f"  px per module : min {min(module_sizes)}  median "
            f"{statistics.median(module_sizes):.2f}  max {max(module_sizes)}"
        )
        emit()
        dead = sum(1 for m in module_sizes if m < 2.0)
        marginal = sum(1 for m in module_sizes if 2.0 <= m < 3.0)
        healthy = sum(1 for m in module_sizes if m >= 3.0)
        emit(f"  below 2.0 px/module (unrecoverable) : {dead}/{len(module_sizes)}")
        emit(f"  2.0 - 3.0        (marginal)         : {marginal}/{len(module_sizes)}")
        emit(f"  above 3.0        (should decode)    : {healthy}/{len(module_sizes)}")
        emit()
        if dead > len(module_sizes) / 2:
            emit("  >>> VERDICT: mostly a CAPTURE problem. The information is not")
            emit("      in these files. No software change recovers them — the")
            emit("      upload UI must make people fill the frame.")
        elif healthy + marginal > len(module_sizes) / 2:
            emit("  >>> VERDICT: mostly a SOFTWARE problem. The QRs are big")
            emit("      enough; we are failing to find and isolate them.")

    emit()
    emit("-" * 70)
    emit("H3/H4  WHICH EXPERIMENT RECOVERED IT")
    emit("-" * 70)
    for name, count in winners.most_common():
        emit(f"  {name:<28} {count:>3}/{total}   {count / total:>6.1%}")

    recovered = total - winners["NO_QR_AT_ALL"] - winners["WRONG_QR_ON_THIS_FACE"]
    baseline = winners.get("E0_original", 0)
    emit()
    emit(f"  baseline (what we ship today) : {baseline}/{total}  {baseline / total:.1%}")
    emit(f"  with localise+crop+upscale    : {recovered}/{total}  {recovered / total:.1%}")
    if recovered > baseline:
        emit(f"  >>> a localiser would recover {recovered - baseline} more images")
    else:
        emit("  >>> a localiser recovers NOTHING here. Do not build one yet.")

    if wrong_qr_count:
        emit()
        emit(
            "  *** " + str(wrong_qr_count) + " image(s) contained a QR that is NOT a Secure QR ***"
        )
        emit("  These decoded fine — the face simply does not carry the signed QR.")
        emit("  Newer Aadhaar PVC cards put a short non-Secure QR on the FRONT.")
        emit("  If these are front faces, they are working exactly as designed and")
        emit("  must not be counted as failures. Only ONE face needs the Secure QR.")

    emit()
    emit("-" * 70)
    emit("PER IMAGE")
    emit("-" * 70)
    emit(f"  {'condition':<22}{'MP':>6}{'QRpx':>7}{'px/mod':>8}{'blur':>8}  result")
    for condition, facts, winner in per_image:
        emit(
            f"  {condition:<22}{facts.get('megapixels', 0):>6}"
            f"{facts.get('qr_px', 0):>7}{facts.get('px_per_module', 0):>8}"
            f"{facts.get('blur', 0):>8}  "
            ""
            f"{winner or ('wrong-qr' if facts.get('wrong_qr') else 'no-qr')}"
        )

    emit()
    emit("=" * 70)
    args.out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\nWritten to {args.out.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
