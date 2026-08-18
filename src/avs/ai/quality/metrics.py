"""Capture-quality measurements — Step 14.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 14
Provides : QualityMetrics, measure_quality()
Consumes : avs.imaging.ops, numpy, OpenCV
Used by  : avs.ai.quality.assessor, scripts/measure_decode_quality.py
Status   : COMPLETE

WHAT THIS IS — AND WHAT IT DELIBERATELY IS NOT
----------------------------------------------
Measurement only. Not one threshold lives in this file.

That separation is not tidiness, it is the lesson Step 13 charged for. There the
measurement and the judgement were written together, both from generated images,
and they agreed with each other perfectly while being wrong about reality. When
the numbers can be extracted on their own, they can be paired with REAL decode
outcomes — which is what ``scripts/measure_decode_quality.py`` does — and the
thresholds can then be derived instead of invented.

⛔ WHY THIS COMPONENT IS THE HIGHEST-VALUE ONE IN THE PLAN

   Measured in Step 7.5: an undecodable image burns the FULL variant matrix,
   about 4.3 seconds, proving a negative. Two unreadable sides is ~9 seconds of
   CPU spent discovering nothing, and at the end the employee is told to
   "photograph it in good light" with no idea what was actually wrong.

   Knowing *before* that attempt that the QR is 1.8 pixels per module means
   telling them "move closer, the code is too small to read" — which is
   actionable, specific, and true.

⚠ EVERY FIELD IS A SHAPE STATISTIC

  No text, no payload, no decoded content. Same privacy property as Step 13's
  features: these numbers can leave a machine holding real cards.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from avs.imaging.ops import (
    estimate_blur,
    estimate_glare_fraction,
    find_document_quad,
    find_qr_region,
    to_grayscale,
)

__all__ = ["MODULES_ACROSS", "QualityMetrics", "measure_quality"]

#: Modules across a UIDAI Secure QR.
#:
#: ⛔ MUST match `MODULES_ACROSS` in integration/nextjs/lib/captureQuality.ts.
#:    The Aadhaar Secure QR carries ~1.3KB of signed payload, which puts it at
#:    QR version 21-22 — 97 to 101 modules. 97 is used as the conservative
#:    figure: assuming FEWER modules than reality would overestimate pixels per
#:    module and let a too-small capture through.
MODULES_ACROSS = 97


@dataclass(frozen=True, slots=True)
class QualityMetrics:
    """What can be measured about a capture, before anyone tries to decode it.

    ⛔ Descriptive only. Nothing here says "good" or "bad" — that judgement
       needs thresholds, thresholds need real decode outcomes, and those live in
       ``assessor.py`` where they can be argued with and re-measured.
    """

    width: int
    height: int
    megapixels: float

    px_per_module: float | None
    """★ THE PREDICTOR. QR width in pixels / MODULES_ACROSS.

    Step 11 measured the relationship on real captures: below ~2.0 nothing was
    recoverable by any preprocessing strategy, because the information is simply
    not in the file. Above ~4 decoding was reliable.

    ``None`` means no QR was located — which is NOT the same as "too small", and
    must not be conflated with it. One means "move closer", the other means "we
    cannot see a code at all"."""

    qr_area_fraction: float
    """How much of the frame the QR occupies. Distinguishes "far away" from
    "close but low-resolution", which need different advice."""

    qr_fully_inside: bool
    """Is the LOCATED region clear of the frame edge?

    ⚠ WEAKER THAN IT SOUNDS — measured, not assumed. It cannot detect "the real
      QR was cut off", because when the true code is clipped the finder-pattern
      search does not report a clipped code: it silently relocates to the next
      best candidate elsewhere on the card (observed: px_per_module collapsing
      from ~7 to 1.9). See D136.

      So read this as "the thing I found is not against the border", not as
      "the QR is intact". Step 15's trained localiser is what can make the
      stronger claim, because it can be scored on finding the RIGHT region."""

    sharpness: float
    """Variance of Laplacian. Step 7.5 measured the `phone-a-dim` failures at
    6.7-11.7 and good captures far above that."""

    glare_fraction: float
    """Fraction of near-white blown-out pixels. Glare over the QR destroys
    modules; glare elsewhere on the card is harmless — hence the next field."""

    glare_over_qr: float
    """⚠ Glare *within the QR region specifically*. The whole-frame figure is
    misleading: a bright window behind the card inflates it while the code
    itself is perfectly readable."""

    mean_brightness: float
    shadow_range: float
    """Difference between the brightest and darkest local regions. High values
    mean uneven lighting — a hand shadow across part of the card — which needs
    different advice from "too dark overall"."""

    skew_degrees: float
    """Rotation of the document quad from square. Perspective distortion is
    correctable up to a point; past it the modules smear."""

    def as_row(self) -> dict[str, float]:
        """A flat, loggable record. Numbers only — safe to share."""
        return {
            "megapixels": round(self.megapixels, 3),
            "px_per_module": round(self.px_per_module, 3) if self.px_per_module else 0.0,
            "qr_located": float(self.px_per_module is not None),
            "qr_area_fraction": round(self.qr_area_fraction, 4),
            "qr_fully_inside": float(self.qr_fully_inside),
            "sharpness": round(self.sharpness, 2),
            "glare_fraction": round(self.glare_fraction, 4),
            "glare_over_qr": round(self.glare_over_qr, 4),
            "mean_brightness": round(self.mean_brightness, 2),
            "shadow_range": round(self.shadow_range, 2),
            "skew_degrees": round(self.skew_degrees, 2),
        }


#: Long edge used for the whole-frame statistics.
#:
#: ⚠ QR geometry is measured at FULL resolution, not here. Downscaling before
#:   measuring pixels-per-module would measure the downscale, not the capture —
#:   which is the single number this whole component rests on.
_WORKING_EDGE = 1400


def measure_quality(image: np.ndarray) -> QualityMetrics:
    """Measure a capture. Never raises — a failed measurement is a neutral value.

    ⛔ Every measurement is individually guarded. This is an advisory component
       and must never be the reason a verification fails (D120).
    """
    if image is None or image.size == 0:
        return _empty(0, 0)

    height, width = image.shape[:2]
    full_grey = _safe(lambda: to_grayscale(image), None)
    if full_grey is None:
        return _empty(width, height)

    # ★ At FULL resolution. See the note on _WORKING_EDGE.
    region = _safe(lambda: find_qr_region(full_grey), None)

    px_per_module: float | None = None
    qr_area_fraction = 0.0
    qr_fully_inside = False
    glare_over_qr = 0.0

    if region is not None:
        x, y, qr_w, qr_h = region
        # The QR is square; the shorter side is the honest figure, because a
        # skewed capture makes one axis look larger than the code really is.
        px_per_module = float(min(qr_w, qr_h)) / MODULES_ACROSS
        qr_area_fraction = min(1.0, float(qr_w * qr_h) / float(width * height or 1))

        # ⛔ PROPORTIONAL, NOT A FIXED 2px — measured, not assumed.
        #
        #    `find_qr_region` reports the box spanning the finder patterns, which
        #    EXCLUDES the QR's quiet zone. Measured on a real encoded QR placed
        #    at a known position: a 700px code reported as (26, 26, 649, 649) —
        #    inset by 26px, ~4% per side, on every placement tested.
        #
        #    A fixed 2px margin therefore could never fire: even a code jammed
        #    against the frame corner reports x=26, which clears it. The first
        #    version of this check was True for every input, including a QR
        #    placed at (0, 0).
        #
        #    6% covers the measured 4% inset plus the 4-module quiet zone the QR
        #    spec requires for decoding — a code without its quiet zone is at
        #    risk whether or not the pixels are technically inside the frame.
        quiet_zone = max(2, int(0.06 * min(qr_w, qr_h)))
        qr_fully_inside = (
            x > quiet_zone
            and y > quiet_zone
            and (x + qr_w) < (width - quiet_zone)
            and (y + qr_h) < (height - quiet_zone)
        )

        patch = full_grey[max(0, y) : y + qr_h, max(0, x) : x + qr_w]
        if patch.size:
            glare_over_qr = _safe(lambda: float(np.mean(patch > 240)), 0.0)

    working = _downscale(image)
    grey = _safe(lambda: to_grayscale(working), full_grey)

    quad = _safe(lambda: find_document_quad(working), None)

    return QualityMetrics(
        width=width,
        height=height,
        megapixels=width * height / 1_000_000,
        px_per_module=px_per_module,
        qr_area_fraction=qr_area_fraction,
        qr_fully_inside=qr_fully_inside,
        sharpness=_safe(lambda: estimate_blur(grey), 0.0),
        glare_fraction=_safe(lambda: estimate_glare_fraction(grey), 0.0),
        glare_over_qr=glare_over_qr,
        mean_brightness=_safe(lambda: float(np.mean(grey)), 0.0),
        shadow_range=_safe(lambda: _shadow_range(grey), 0.0),
        skew_degrees=_safe(lambda: _skew_degrees(quad), 0.0),
    )


# --------------------------------------------------------------------------- #
# Individual measurements
# --------------------------------------------------------------------------- #


def _shadow_range(grey: np.ndarray) -> float:
    """Spread of local brightness across the frame, 0-255.

    ⚠ Deliberately not the global min/max, which any single blown highlight or
      dark speck would saturate. Downsampling to a coarse grid first measures
      how brightness varies across REGIONS, which is what a hand shadow or a
      lamp on one side actually does.
    """
    import cv2

    coarse = cv2.resize(grey, (8, 8), interpolation=cv2.INTER_AREA).astype(np.float64)
    return float(coarse.max() - coarse.min())


def _skew_degrees(quad: np.ndarray | None) -> float:
    """How far the document quad is from square, in degrees.

    Returns 0.0 when no quad was found — "unknown" reported as "fine", because
    an advisory metric must not invent a problem it cannot see. A real skew
    problem shows up in px_per_module and sharpness anyway.
    """
    if quad is None or len(quad) != 4:
        return 0.0

    points = np.asarray(quad, dtype=np.float64).reshape(4, 2)
    angles = []
    for index in range(4):
        edge = points[(index + 1) % 4] - points[index]
        angle = np.degrees(np.arctan2(edge[1], edge[0])) % 90.0
        angles.append(min(angle, 90.0 - angle))
    return float(np.mean(angles))


def _downscale(image: np.ndarray) -> np.ndarray:
    height, width = image.shape[:2]
    long_edge = max(height, width)
    if long_edge <= _WORKING_EDGE:
        return image

    import cv2

    scale = _WORKING_EDGE / long_edge
    return cv2.resize(
        image,
        (max(1, int(width * scale)), max(1, int(height * scale))),
        interpolation=cv2.INTER_AREA,
    )


def _safe(measure, default):  # type: ignore[no-untyped-def]
    """Run a measurement, or return the neutral value. See D120."""
    try:
        return measure()
    except BaseException:
        return default


def _empty(width: int, height: int) -> QualityMetrics:
    return QualityMetrics(
        width=width,
        height=height,
        megapixels=width * height / 1_000_000,
        px_per_module=None,
        qr_area_fraction=0.0,
        qr_fully_inside=False,
        sharpness=0.0,
        glare_fraction=0.0,
        glare_over_qr=0.0,
        mean_brightness=0.0,
        shadow_range=0.0,
        skew_degrees=0.0,
    )
