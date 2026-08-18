"""ONNX-backed document classifier — Step 13.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 13
Provides : OnnxDocumentClassifier, MODEL_NAME, CLASS_ORDER
Consumes : avs.ai.modelmgr, avs.ai.classify.features
Used by  : avs.ai.classify.build_classifier()
Status   : COMPLETE — the seam is finished; no model file ships yet

WHY THIS EXISTS WITH NO MODEL BEHIND IT
---------------------------------------
A trained classifier needs labelled Aadhaar images, and those live only on one
machine and stay there — see the corpus rule in PROJECT_STATE.md. So Step 13
ships the seam rather than the weights: everything needed to drop a model in
later, with the failure behaviour already proven by tests.

That ordering is deliberate. Wiring a model in is where the mistakes happen —
a wrong class order, an unhandled load failure, a silent shape mismatch. Doing
that work now, with fakes that can be made to misbehave on purpose, is far
safer than doing it in the same change that first introduces real weights.

⛔ CLASS ORDER IS PART OF THE CONTRACT

   ``CLASS_ORDER`` must match the order the model was trained with, exactly. Get
   it wrong and nothing crashes — the model simply reports "Aadhaar front" when
   it means "not a document", confidently. That is the worst kind of bug: silent,
   plausible, and invisible to every test that only checks the code runs.

   So the order lives here as a named constant, is asserted by a test, and is
   recorded in ``models.json`` alongside the digest. A model whose declared
   ``output_names`` disagree with this list is refused rather than trusted.
"""

from __future__ import annotations

import numpy as np

from avs.ai.classify.features import extract_features
from avs.ai.modelmgr import ModelRunner
from avs.contracts import DocType, DocTypePrediction, ValidatedImage
from avs.logging import get_logger

__all__ = ["CLASS_ORDER", "MODEL_NAME", "OnnxDocumentClassifier"]

log = get_logger(__name__)

#: Registry key. Must match the ``name`` in ``models/models.json``.
MODEL_NAME = "doc_classifier"

#: ⛔ The order the model's output vector is interpreted in. Changing this
#:    without retraining silently relabels every prediction. See the module
#:    docstring — a mismatch here produces confident nonsense, not an error.
CLASS_ORDER: tuple[DocType, ...] = (
    DocType.AADHAAR_FRONT,
    DocType.AADHAAR_BACK,
    DocType.AADHAAR_PVC,
    DocType.OTHER_ID,
    DocType.NOT_A_DOCUMENT,
)

#: Below this the model is not confident enough to be worth acting on, so the
#: prediction is reported as UNKNOWN.
#:
#: ⚠ Deliberately high. The only thing a prediction changes is which message an
#:   employee reads after a failure they are already having. Being confidently
#:   wrong about that is worse than saying nothing, because a specific wrong
#:   instruction sends someone off to fix the wrong problem.
MIN_CONFIDENCE = 0.75

#: Model input edge. Recorded here because the preprocessing must match training
#: exactly; a model fed differently-scaled images degrades quietly rather than
#: failing, which is the hardest kind of regression to notice.
INPUT_EDGE = 224


class OnnxDocumentClassifier:
    """Implements ``DocumentClassifier`` against a model in the registry.

    Degrades to ``UNKNOWN`` whenever the model is absent, unpinned, broken, slow
    or unconvincing — which is every state it can be in other than working.
    """

    name = MODEL_NAME

    def __init__(self, runner: ModelRunner, *, min_confidence: float = MIN_CONFIDENCE) -> None:
        self.runner = runner
        self.min_confidence = min_confidence

    def classify(self, image: ValidatedImage) -> DocTypePrediction:
        """Classify via the model. Never raises — see D120."""
        try:
            tensor = self._preprocess(image)
        except BaseException as exc:
            log.warning("ai.classify.preprocess_failed", error=type(exc).__name__)
            return self._unknown()

        if tensor is None:
            return self._unknown()

        outcome = self.runner.run(MODEL_NAME, {"input": tensor})
        if outcome is None or not outcome.usable:
            # Absent model, failed digest, timeout, crash — all the same to the
            # caller: no opinion, carry on deterministically.
            return self._unknown()

        return self._interpret(outcome.outputs, outcome.version)

    # ------------------------------------------------------------------ #

    def _interpret(self, outputs: tuple, version: str) -> DocTypePrediction:
        """Turn a raw output vector into a prediction, or into UNKNOWN.

        ⛔ Every shape assumption is checked. A model that returns the wrong
           number of classes is a model that was swapped or retrained without
           updating CLASS_ORDER, and guessing at its meaning would produce
           exactly the silent relabelling this module exists to prevent.
        """
        try:
            scores = np.asarray(outputs[0], dtype=np.float64).ravel()
        except BaseException:
            return self._unknown()

        if scores.size != len(CLASS_ORDER):
            log.error(
                "ai.classify.shape_mismatch",
                expected=len(CLASS_ORDER),
                received=int(scores.size),
                model_version=version,
            )
            return self._unknown()

        if not np.all(np.isfinite(scores)):
            # NaN propagates silently through argmax and comparisons.
            log.warning("ai.classify.non_finite_output", model_version=version)
            return self._unknown()

        probabilities = _softmax(scores)
        index = int(np.argmax(probabilities))
        confidence = float(probabilities[index])

        if confidence < self.min_confidence:
            return self._unknown(version)

        return DocTypePrediction(
            doc_type=CLASS_ORDER[index],
            confidence=confidence,
            model_version=version,
        )

    def _preprocess(self, image: ValidatedImage) -> np.ndarray | None:
        """Decode, resize and normalise to NCHW float32.

        ⚠ Must match training preprocessing exactly. Recorded in one place so
          that when the model is trained, there is a single definition to match
          rather than an assumption to rediscover.
        """
        import cv2

        buffer = np.frombuffer(image.data, dtype=np.uint8)
        decoded = cv2.imdecode(buffer, cv2.IMREAD_COLOR)
        if decoded is None or decoded.size == 0:
            return None

        resized = cv2.resize(decoded, (INPUT_EDGE, INPUT_EDGE), interpolation=cv2.INTER_AREA)
        rgb = cv2.cvtColor(resized, cv2.COLOR_BGR2RGB).astype(np.float32) / 255.0
        return np.transpose(rgb, (2, 0, 1))[np.newaxis, ...]

    def _unknown(self, version: str | None = None) -> DocTypePrediction:
        return DocTypePrediction(doc_type=DocType.UNKNOWN, confidence=0.0, model_version=version)

    # Kept so the training pipeline and the runtime agree on features.
    extract_features = staticmethod(extract_features)


def _softmax(scores: np.ndarray) -> np.ndarray:
    """Numerically stable softmax.

    ⚠ Subtracting the max first is not a nicety: raw logits from a vision model
      routinely exceed 700, and ``exp(710)`` overflows float64 to ``inf``,
      making every probability NaN.
    """
    shifted = scores - np.max(scores)
    exponentiated = np.exp(shifted)
    total = np.sum(exponentiated)
    if total <= 0 or not np.isfinite(total):
        return np.full_like(scores, 1.0 / scores.size)
    return exponentiated / total
