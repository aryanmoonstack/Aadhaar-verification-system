"""Image features for document classification — Step 13.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 13
Provides : DocumentFeatures, extract_features()
Consumes : avs.imaging.ops, numpy, OpenCV
Used by  : avs.ai.classify.heuristic, avs.ai.classify.onnx
Status   : COMPLETE

WHAT THIS IS
------------
Pure measurement. Every function here answers a question about pixels and
nothing else — is there a rectangular document boundary, is there a QR, how much
edge structure is present, how colourful is it. No thresholds that decide
anything live here; they live in ``heuristic.py`` where they can be argued with.

Separating measurement from judgement matters for a reason this project has
already been bitten by. In Step 7.5 a broken QR localiser reported "QR not
located" for 22 images including five it had just decoded, because the
measurement and the decision were tangled in the same ``try/except``. When the
numbers are extractable on their own, they can be printed, compared against real
images, and disagreed with.

⚠ EVERY FEATURE IS SHAPE, NEVER CONTENT

  Nothing here reads text, decodes a QR payload, or extracts a number. These are
  geometry and statistics: sizes, ratios, densities. That is deliberate — the
  features can be logged, written to a CSV, and used to train a model without a
  single Aadhaar detail leaving the machine the images are on.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from avs.imaging.ops import (
    estimate_blur,
    find_document_quad,
    find_qr_region,
    to_grayscale,
)

__all__ = ["DocumentFeatures", "extract_features"]


@dataclass(frozen=True, slots=True)
class DocumentFeatures:
    """What we can measure about an image without understanding it.

    ⛔ Everything here is a number about pixels. No field holds text, a decoded
       payload, or anything derived from Aadhaar content — see the module
       docstring. This is what makes the features safe to log and safe to send
       off a machine holding real cards.
    """

    width: int
    height: int

    aspect_ratio: float
    """Long edge / short edge. An Aadhaar card is ISO ID-1, so a well-cropped
    card sits near 1.586. A phone photo of one includes background, so this is
    weak evidence on its own — it is the reason the heuristic never classifies
    on aspect ratio alone."""

    has_document_quad: bool
    """A four-sided bright region was found — the card against a background."""

    quad_area_fraction: float
    """How much of the frame that quad occupies. Near 1.0 means the card fills
    the frame (good); near 0.1 means it is a distant speck (bad)."""

    has_qr: bool
    """Three QR finder patterns were located. ⚠ This says a QR is PRESENT, not
    that it decoded and certainly not that it is a UIDAI Secure QR — those are
    the deterministic path's business."""

    qr_area_fraction: float

    edge_density: float
    """Fraction of pixels on an edge. Documents are dense with text and rules;
    a face, a wall or a sky is not. The single most discriminating feature for
    "is this a document at all"."""

    saturation_mean: float
    """0-255. Identity documents are mostly white with print; photographs of
    people and places are markedly more saturated."""

    dark_fraction: float
    """Fraction of near-black pixels. A very dark frame is usually a failed
    capture rather than a document."""

    mean_brightness: float
    """0-255 mean luminance.

    ⛔ ADDED AFTER REAL MEASUREMENT CONTRADICTED THE DESIGN.

       Dheeraj's `phone-a-dim` Aadhaar cards measured 0.0000-0.0096 edge
       density — identical to a blank wall. Underexposure destroys edge
       structure, so "no edges" cannot distinguish a featureless surface from a
       real card photographed in the dark.

       This is the feature that separates them: a dim card is DARK, a blank
       wall in normal light is not. Without it the edge test is unsafe."""

    blur: float
    """Variance of Laplacian, from Step 4. Carried so a caller can tell "not a
    document" from "a document photographed badly" — which need opposite advice
    and would otherwise get the same message."""

    def as_row(self) -> dict[str, float]:
        """A flat, loggable record. Used by the training-data collector.

        ⚠ Safe to write to disk and safe to send: every value is a shape
          statistic. There is deliberately no field that could carry a name, a
          number or a payload.
        """
        return {
            "aspect_ratio": round(self.aspect_ratio, 4),
            "has_document_quad": float(self.has_document_quad),
            "quad_area_fraction": round(self.quad_area_fraction, 4),
            "has_qr": float(self.has_qr),
            "qr_area_fraction": round(self.qr_area_fraction, 4),
            "edge_density": round(self.edge_density, 4),
            "saturation_mean": round(self.saturation_mean, 2),
            "dark_fraction": round(self.dark_fraction, 4),
            "mean_brightness": round(self.mean_brightness, 2),
            "blur": round(self.blur, 2),
            "megapixels": round(self.width * self.height / 1_000_000, 3),
        }


#: Long edge to work at. Feature extraction does not need full resolution, and a
#: 12MP phone photo costs roughly 40x more to process than a 1000px working copy
#: for measurements that barely move. Step 7.5 measured the same trade for
#: decoding and settled on a similar figure.
_WORKING_EDGE = 1000


def extract_features(image: np.ndarray) -> DocumentFeatures:
    """Measure an image. Never raises — a failed measurement is a neutral value.

    ⛔ Every individual measurement is guarded. A classifier is advisory, so a
       feature that cannot be computed must yield "I don't know" rather than an
       exception that propagates into the pipeline. See D120.
    """
    if image is None or image.size == 0:
        return _empty_features(0, 0)

    height, width = image.shape[:2]
    working = _downscale(image)

    grey = to_grayscale(working)
    work_h, work_w = grey.shape[:2]
    work_area = float(work_h * work_w) or 1.0

    long_edge, short_edge = max(width, height), min(width, height)
    aspect = long_edge / short_edge if short_edge else 0.0

    quad = _safe(lambda: find_document_quad(working), None)
    if quad is not None:
        import cv2

        quad_fraction = min(1.0, float(cv2.contourArea(quad.astype(np.float32))) / work_area)
    else:
        quad_fraction = 0.0

    region = _safe(lambda: find_qr_region(grey), None)
    if region is not None:
        _, _, qr_w, qr_h = region
        qr_fraction = min(1.0, float(qr_w * qr_h) / work_area)
    else:
        qr_fraction = 0.0

    return DocumentFeatures(
        width=width,
        height=height,
        aspect_ratio=aspect,
        has_document_quad=quad is not None,
        quad_area_fraction=quad_fraction,
        has_qr=region is not None,
        qr_area_fraction=qr_fraction,
        edge_density=_safe(lambda: _edge_density(grey), 0.0),
        saturation_mean=_safe(lambda: _saturation_mean(working), 0.0),
        dark_fraction=_safe(lambda: float(np.mean(grey < 40)), 0.0),
        mean_brightness=_safe(lambda: float(np.mean(grey)), 0.0),
        blur=_safe(lambda: estimate_blur(grey), 0.0),
    )


# --------------------------------------------------------------------------- #
# Individual measurements
# --------------------------------------------------------------------------- #


def _edge_density(grey: np.ndarray) -> float:
    """Fraction of pixels lying on a Canny edge.

    ★ The single most useful feature for "is this a document at all". Printed
      matter is dense with high-contrast boundaries — text strokes, rules,
      borders — while a face, a wall or a landscape is mostly smooth gradient.

    The 100/200 thresholds are OpenCV's long-standing defaults; the absolute
    value matters less than the fact that documents and non-documents separate
    by roughly an order of magnitude.
    """
    import cv2

    edges = cv2.Canny(grey, 100, 200)
    return float(np.count_nonzero(edges)) / float(edges.size or 1)


def _saturation_mean(image: np.ndarray) -> float:
    """Mean HSV saturation, 0–255. Greyscale input is by definition unsaturated."""
    if image.ndim == 2:
        return 0.0

    import cv2

    hsv = cv2.cvtColor(image, cv2.COLOR_BGR2HSV)
    return float(np.mean(hsv[:, :, 1]))


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
    """Run a measurement, or return the neutral value.

    ⚠ Broad by design. A feature that cannot be computed is a missing number,
      not an error — and an advisory component must never be the reason a
      verification fails (D120).
    """
    try:
        return measure()
    except BaseException:
        return default


def _empty_features(width: int, height: int) -> DocumentFeatures:
    return DocumentFeatures(
        width=width,
        height=height,
        aspect_ratio=0.0,
        has_document_quad=False,
        quad_area_fraction=0.0,
        has_qr=False,
        qr_area_fraction=0.0,
        edge_density=0.0,
        saturation_mean=0.0,
        dark_fraction=0.0,
        mean_brightness=0.0,
        blur=0.0,
    )
