"""Capture-quality measurements — Step 14.

⛔ THESE TESTS DELIBERATELY ASSERT NO THRESHOLDS.

   Step 13's classifier failed because its thresholds and its tests were written
   from the same generated images, so they agreed with each other and were wrong
   about reality. Asserting "sharpness > 100 means good" here would rebuild that
   trap one level down.

   What IS asserted: that each measurement responds in the right DIRECTION to a
   change it should notice, that nothing raises, and that no field can carry
   Aadhaar content. Where the cut-off falls is `scripts/measure_decode_quality.py`
   paired with real decode outcomes — not this file.
"""

from __future__ import annotations

import numpy as np

from avs.ai.quality import MODULES_ACROSS, measure_quality


def _real_qr(payload_digits: int = 1200) -> np.ndarray:
    """A genuinely decodable QR, not a random grid.

    ⚠ A random black-and-white grid LOOKS like a QR to a finder-pattern search
      and decodes to nothing. Using a real encoder means these fixtures exercise
      the same path a real card does.
    """
    import cv2

    rng = np.random.default_rng(3)
    payload = "".join(str(int(d)) for d in rng.integers(0, 10, payload_digits))
    return cv2.QRCodeEncoder_create().encode(payload)


def card(qr_px: int = 700, *, blur: int = 0, brightness: float = 1.0) -> np.ndarray:
    """A document-shaped frame with a real QR at a controlled pixel size."""
    import cv2

    rng = np.random.default_rng(3)
    width, height = 2400, 1500
    frame = np.full((height + 400, width + 400, 3), 60, np.uint8)
    face = np.full((height, width, 3), 245, np.uint8)

    for index in range(30):
        y = 90 + index * 40
        cv2.line(face, (60, y), (60 + int(rng.integers(400, width - 500)), y), (25, 25, 25), 7)

    qr = cv2.cvtColor(
        cv2.resize(_real_qr(), (qr_px, qr_px), interpolation=cv2.INTER_NEAREST),
        cv2.COLOR_GRAY2BGR,
    )
    face[height - qr_px - 60 : height - 60, width - qr_px - 60 : width - 60] = qr
    frame[200 : 200 + height, 200 : 200 + width] = face

    if blur:
        frame = cv2.GaussianBlur(frame, (blur | 1, blur | 1), 0)
    if brightness != 1.0:
        frame = np.clip(frame.astype(np.float64) * brightness, 0, 255).astype(np.uint8)
    return frame


# --------------------------------------------------------------------------- #
# Direction, not magnitude
# --------------------------------------------------------------------------- #


def test_px_per_module_falls_when_the_image_is_downscaled():
    """★ THE PREDICTOR. It must track the actual size of the code on screen.

    Asserted as a RATIO rather than an absolute, because the absolute depends on
    how the localiser bounds the QR and that is not what this measures.
    """
    import cv2

    full = measure_quality(card(700))
    half = measure_quality(cv2.resize(card(700), None, fx=0.5, fy=0.5))

    assert full.px_per_module is not None
    assert half.px_per_module is not None
    assert half.px_per_module < full.px_per_module


def test_px_per_module_is_computed_at_full_resolution():
    """⛔ If the metric were taken after downscaling, it would measure the
    downscale rather than the capture — and this whole component rests on it.

    A 700px QR over 97 modules is ~7.2 px/module. Measured at a 1400px working
    edge on a 2800px frame it would halve.
    """
    metrics = measure_quality(card(700))

    assert metrics.px_per_module is not None
    assert metrics.px_per_module > 3.0, (
        f"got {metrics.px_per_module:.2f} — suspiciously low for a 700px QR, "
        f"which suggests the measurement ran on a downscaled copy"
    )


def test_sharpness_falls_when_blurred():
    assert measure_quality(card(700, blur=15)).sharpness < measure_quality(card(700)).sharpness


def test_mean_brightness_falls_when_darkened():
    dim = measure_quality(card(700, brightness=0.25))
    lit = measure_quality(card(700))

    assert dim.mean_brightness < lit.mean_brightness


def test_a_missing_qr_reports_none_not_zero():
    """⛔ "No code visible" and "code too small" need OPPOSITE advice.

    None means we cannot see a code at all. 0.0 would silently mean "infinitely
    small", and would be compared against a threshold as if it were a
    measurement — turning "I don't know" into "definitely too small".
    """
    blank = np.full((1200, 1600, 3), 200, np.uint8)
    metrics = measure_quality(blank)

    assert metrics.px_per_module is None


def test_qr_fully_inside_detects_a_code_against_the_frame_edge():
    """★ WHAT THIS FIELD CAN AND CANNOT DO — corrected by a failing test.

    The first version of this test cut the frame so the real QR ran off the
    edge, and expected `qr_fully_inside is False`. It came back True.

    The reason matters and is D136: with the real QR clipped, the localiser did
    not report a clipped QR — it silently relocated to a FALSE POSITIVE
    elsewhere on the card (px_per_module collapsed from ~7 to 1.9, a region
    ~183px wide). Finder-pattern search returns the best candidate it finds, not
    the one we meant.

    So this field cannot detect "the code I care about was cut off". It can only
    detect "the region I located touches the border", which is still worth
    having and is what is asserted here. The stronger claim belongs to Step 15's
    trained localiser, which can be scored on whether it found the RIGHT region.
    """
    import cv2

    intact = measure_quality(card(700))
    assert intact.qr_fully_inside is True

    # A QR hard against the top-left corner: nothing else for the localiser to
    # prefer, so the region it reports IS the one at the border.
    qr = cv2.cvtColor(
        cv2.resize(_real_qr(), (700, 700), interpolation=cv2.INTER_NEAREST), cv2.COLOR_GRAY2BGR
    )
    edge_frame = np.full((1200, 1600, 3), 245, np.uint8)
    edge_frame[0:700, 0:700] = qr

    assert measure_quality(edge_frame).qr_fully_inside is False


def test_glare_over_qr_is_separate_from_whole_frame_glare():
    """⚠ A bright window behind the card inflates whole-frame glare while the
    code itself stays perfectly readable. Conflating the two would send someone
    to fix lighting that is not the problem."""
    import cv2

    frame = card(700)
    cv2.rectangle(frame, (50, 50), (700, 700), (255, 255, 255), -1)  # blown highlight, far from QR

    metrics = measure_quality(frame)

    assert metrics.glare_fraction > 0.0
    assert metrics.glare_over_qr < metrics.glare_fraction


# --------------------------------------------------------------------------- #
# Robustness and privacy
# --------------------------------------------------------------------------- #


def test_measurement_never_raises_on_junk():
    for bad in (
        np.zeros((0, 0, 3), np.uint8),
        np.zeros((1, 1, 3), np.uint8),
        np.full((10, 10), 128, np.uint8),
    ):
        measure_quality(bad)  # must not raise


def test_every_metric_is_a_number():
    """⛔ The privacy property that lets these values leave a machine holding
    real cards. No field may carry text, a payload, or a filename."""
    row = measure_quality(card(700)).as_row()

    assert all(isinstance(value, (int, float)) for value in row.values())
    assert not {"payload", "text", "name", "uid", "aadhaar", "filename"} & set(row)


def test_the_browser_no_longer_hard_codes_the_shared_constants():
    """⛔ SUPERSEDED BY GENERATION — Step 14.

    This used to assert that the literal `MODULES_ACROSS = 97` appeared in
    `captureQuality.ts`. That check could only ever catch ONE constant, and it
    missed the one that mattered: `MIN_MEGAPIXELS = 4`, hand-set from a corpus
    of 22 images, still sitting there after the corpus grew to 27 and made it
    wrong. The browser was warning about photos the server decoded.

    The shared values are now imported from `thresholds.generated.ts`, so a
    literal here is a regression — someone has hand-edited what should be
    generated.
    """
    from pathlib import Path

    source = (
        Path(__file__).resolve().parents[2] / "integration" / "nextjs" / "lib" / "captureQuality.ts"
    )
    if not source.is_file():
        return  # integration not present in this checkout

    text = source.read_text(encoding="utf-8")

    assert "thresholds.generated" in text, "the browser must import the generated values"
    assert "export const MODULES_ACROSS = 97" not in text, "hard-coded again"
    assert "export const MIN_MEGAPIXELS = 4" not in text, "the drifted value is back"


def test_the_generated_browser_thresholds_are_up_to_date():
    """⛔ THE DRIFT GUARD.

    The browser's thresholds were hand-maintained until Step 14 and silently
    diverged: it refused anything under 4 MP while the weakest capture that
    ACTUALLY DECODED measured 2.31 MP — a false warning on a photo the server
    reads perfectly well. Nothing connected the two, so nothing noticed.

    `thresholds.generated.ts` is now written from `ai/quality/assessor.py`. If
    someone changes a server threshold and forgets to re-export, this fails.

        python scripts/export_thresholds.py
    """
    import re
    from pathlib import Path

    from avs.ai.quality import PRE_UPLOAD

    generated = (
        Path(__file__).resolve().parents[2]
        / "integration"
        / "nextjs"
        / "lib"
        / "thresholds.generated.ts"
    )
    if not generated.is_file():
        return  # integration not present in this checkout

    text = generated.read_text(encoding="utf-8")

    def constant(name: str) -> float:
        match = re.search(rf"export const {name} = ([0-9.]+);", text)
        assert match, f"{name} missing from the generated file"
        return float(match.group(1))

    assert constant("MODULES_ACROSS") == MODULES_ACROSS
    assert constant("MIN_PX_PER_MODULE") == PRE_UPLOAD.px_per_module
    assert constant("MIN_MEAN_BRIGHTNESS") == PRE_UPLOAD.mean_brightness


def test_sharpness_is_not_exported_to_the_browser():
    """⚠ The server floor is an OpenCV variance-of-Laplacian value. The browser
    measures no sharpness, and a JavaScript implementation would not share that
    scale — a number copied across would look authoritative and mean nothing."""
    from pathlib import Path

    generated = (
        Path(__file__).resolve().parents[2]
        / "integration"
        / "nextjs"
        / "lib"
        / "thresholds.generated.ts"
    )
    if not generated.is_file():
        return

    text = generated.read_text(encoding="utf-8")
    assert "MIN_SHARPNESS" not in text
    assert "368.76" not in text and "250" not in text
