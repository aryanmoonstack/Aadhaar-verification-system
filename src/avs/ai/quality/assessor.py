"""Capture quality assessment — Step 14.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 14
Provides : HeuristicQualityAssessor, THRESHOLDS
Consumes : avs.ai.quality.metrics, avs.contracts
Used by  : avs.pipeline (optional), avs.cli
Status   : COMPLETE

⛔ EVERY THRESHOLD HERE WAS MEASURED, NOT CHOSEN

   Derived from 27 real Aadhaar photographs run through the ACTUAL decoder —
   `scripts/measure_decode_quality.py` — not from generated images. Step 13's
   classifier was tuned on generated data, agreed with itself perfectly, and
   caught 0 of 19 real cases. This does not repeat that.

   THE MEASUREMENT (8 decoded, 19 failed)::

       metric            floor   catches   false alarms
       sharpness        368.76       68%              0
       mean_brightness  108.73       37%              0
       px_per_module      2.74       21%              0

   Combined, sharpness + brightness flag **79%** of failures having never
   rejected an image that actually worked.

   `px_per_module` adds ZERO on top of those two — every image it catches is
   already caught. It is measured and reported, but deliberately not used as a
   rule, because a rule that never fires alone is code with no reason to exist.

⛔ TWO SETS OF THRESHOLDS, AND WHY

   POST_FAILURE — used server-side, AFTER a verification has already failed.
                  There is no false-alarm risk here BY CONSTRUCTION: the image
                  demonstrably did not decode, so explaining why cannot be
                  wrong about whether it worked. These sit at the measured
                  floor, for maximum explanatory coverage.

   PRE_UPLOAD   — used by the browser, BEFORE anything is sent. A false warning
                  here tells someone their perfectly good photo is bad and
                  makes them retake it for nothing. These sit well BELOW the
                  measured floor, trading coverage for not crying wolf.

   With only 8 successful decodes, a threshold placed exactly at the weakest one
   is fitted to that single image. Which is tolerable when the photo has already
   failed, and not when it hasn't.

⚠ WHAT THIS CANNOT EXPLAIN

   4 of the 19 failures pass every threshold — sharp, bright, well-sized, and
   still undecodable. They are not covered by any rule here and the assessor
   says so rather than inventing a reason. That population is what a trained
   model would have to earn its place on, and what Steps 15/19 target.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from avs.ai.quality.metrics import QualityMetrics, measure_quality
from avs.contracts import QualityScores, ValidatedImage
from avs.logging import get_logger

__all__ = ["POST_FAILURE", "PRE_UPLOAD", "HeuristicQualityAssessor", "QualityThresholds"]

log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class QualityThresholds:
    """One set of measured floors."""

    sharpness: float
    mean_brightness: float
    px_per_module: float
    label: str


#: Server-side, after a failure. At the measured floor — no false-alarm risk,
#: because the image has already demonstrably failed to decode.
POST_FAILURE = QualityThresholds(
    sharpness=368.76,
    mean_brightness=108.73,
    px_per_module=2.74,
    label="post-failure",
)

#: Browser, before upload. ~30% below the measured floor.
#:
#: ⚠ The margin is the whole point. 8 successes cannot support a tight cutoff,
#:   and here a false warning costs a real person a pointless retake. Coverage
#:   drops from 68% to about 58%; that is the correct trade when the photo has
#:   not yet been given a chance.
PRE_UPLOAD = QualityThresholds(
    sharpness=250.0,
    mean_brightness=80.0,
    px_per_module=2.0,
    label="pre-upload",
)


class HeuristicQualityAssessor:
    """Implements the ``QualityAssessor`` Protocol from measured thresholds.

    ⛔ ADVISORY ONLY. Nothing here can reject an image, skip a decode attempt,
       or influence a verdict. It produces scores and, through the pipeline, a
       more specific sentence for someone whose upload has already failed.
    """

    name = "quality-heuristic-v1"

    def __init__(self, thresholds: QualityThresholds = POST_FAILURE) -> None:
        self.thresholds = thresholds

    def assess(self, image: ValidatedImage) -> QualityScores:
        """Score a capture. Never raises — see D120.

        This satisfies the ``QualityAssessor`` Protocol. Callers wanting the
        named problems as well should use `assess_detailed`, which produces both
        from one pass over the pixels.
        """
        return self.assess_detailed(image)[0]

    def assess_detailed(self, image: ValidatedImage) -> tuple[QualityScores, tuple[str, ...]]:
        """Scores AND the named problems, from a SINGLE measurement pass.

        ⛔ STATELESS BY DESIGN. The obvious alternative — `assess()` followed by
           a `last_problems()` that reads what the previous call stored — would
           be shared mutable state on an object the worker pool calls
           concurrently. Two documents assessed at once would race, and the
           symptom would be one employee shown the other's advice.

        ⚠ One pass matters for cost too: the pipeline needs the scores to order
          the variant matrix and the problem names to write the failure message.
          Measuring twice would double the work for an identical answer.
        """
        try:
            decoded = self._decode(image)
            metrics = measure_quality(decoded) if decoded is not None else None
        except BaseException as exc:
            log.warning("ai.quality.failed", error=type(exc).__name__)
            metrics = None

        if metrics is None:
            return self._unknown(), ()

        return self.score(metrics), tuple(self.problems(metrics))

    def score(self, metrics: QualityMetrics) -> QualityScores:
        """The judgement, separated from image handling so it can be tested on
        numbers measured elsewhere — including on a machine this code never
        sees."""
        thresholds = self.thresholds

        # ⚠ Normalised to 0-1 against the measured floor, then clamped. A score
        #   of 1.0 means "at or above the weakest capture that actually worked",
        #   NOT "perfect" — there is no evidence in this corpus about what
        #   perfect looks like.
        blur = _ratio(metrics.sharpness, thresholds.sharpness)
        glare = 1.0 - min(1.0, metrics.glare_over_qr)

        return QualityScores(
            blur=blur,
            glare=glare,
            skew_degrees=metrics.skew_degrees,
            resolution_adequate=(
                metrics.px_per_module is not None
                and metrics.px_per_module >= thresholds.px_per_module
            ),
            crop_complete=metrics.qr_fully_inside,
            shadow=1.0 - min(1.0, metrics.shadow_range / 255.0),
            decodability=self._decodability(metrics),
            model_version=f"{self.name}/{thresholds.label}",
        )

    def problems(self, metrics: QualityMetrics) -> list[str]:
        """Machine-readable reasons, most likely first.

        ⛔ Ordered by MEASURED coverage, not by intuition: sharpness catches 68%
           of failures, brightness a further 11%, and px_per_module nothing at
           all on top of those. Listing them in any other order would put the
           least useful advice first.
        """
        found: list[str] = []
        if metrics.sharpness < self.thresholds.sharpness:
            found.append("blurry")
        if metrics.mean_brightness < self.thresholds.mean_brightness:
            found.append("too_dark")
        if metrics.px_per_module is None:
            found.append("no_code_visible")
        elif metrics.px_per_module < self.thresholds.px_per_module:
            found.append("code_too_small")
        if not metrics.qr_fully_inside and metrics.px_per_module is not None:
            found.append("code_at_edge")
        return found

    # ------------------------------------------------------------------ #

    def _decodability(self, metrics: QualityMetrics) -> float:
        """Predicted probability the QR will decode.

        ⚠ NOT a calibrated probability, and deliberately capped below 1.0.

          The corpus decode rate is 30%, and 4 of 19 failures pass every check
          here. So even a capture that satisfies everything measured has a real
          chance of failing for reasons this component cannot see. Reporting
          0.95 for such an image would be a confident lie; 0.75 is honest about
          how much is actually known.
        """
        if metrics.px_per_module is None:
            return 0.05

        failures = len(self.problems(metrics))
        if failures == 0:
            return 0.75
        return max(0.02, 0.5 ** (failures + 1))

    def _unknown(self) -> QualityScores:
        return QualityScores(
            blur=0.0,
            glare=0.0,
            skew_degrees=0.0,
            resolution_adequate=False,
            crop_complete=False,
            shadow=0.0,
            decodability=0.0,
            model_version=self.name,
        )

    @staticmethod
    def _decode(image: ValidatedImage) -> np.ndarray | None:
        import cv2

        buffer = np.frombuffer(image.data, dtype=np.uint8)
        decoded = cv2.imdecode(buffer, cv2.IMREAD_COLOR)
        return decoded if decoded is not None and decoded.size else None


def _ratio(value: float, floor: float) -> float:
    """value/floor, clamped to 0-1. Floors are measured, never zero."""
    if floor <= 0:
        return 0.0
    return float(min(1.0, max(0.0, value / floor)))
