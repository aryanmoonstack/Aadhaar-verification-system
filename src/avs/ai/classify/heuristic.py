"""Heuristic document classifier — Step 13.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 13
Provides : HeuristicClassifier
Consumes : avs.ai.classify.features, avs.contracts
Used by  : avs.ai.classify.build_classifier()
Status   : ⛔ RETIRED FROM PRODUCTION — kept as reference + diagnostics

⛔⛔ RETIRED BY MEASUREMENT — 17 August 2026

   Run against 19 real wrong-upload images (screenshots, UI mockups, a
   keyboard, a desk, a sunset, a face, a waveform graphic), this classifier
   caught **0 of 19**. It never fires on anything a real employee would
   plausibly upload by mistake.

   THE FEATURE RANGES, MEASURED::

                      edge density        brightness
       DOCUMENTS   0.0000 - 0.1232      41.0 - 174.6
       NEGATIVES   0.0031 - 0.0886       3.7 - 235.2

   The negative range sits ENTIRELY INSIDE the document range on edge density —
   100% overlap. No threshold on these features separates the classes, so this
   is not a tuning problem and no amount of adjustment fixes it.

   WHY, in one sentence: a screenshot of text IS a document image, just not an
   Aadhaar one. Shape statistics describe how an image is STRUCTURED; telling an
   Aadhaar from a PAN card or a chat screenshot requires knowing what it SAYS.
   That is what the trained model in ``onnx.py`` is for.

   The one thing this could detect — a well-lit, completely featureless frame —
   turns out not to occur. People do not photograph blank walls and upload them;
   they upload screenshots and photos of things, all of which have structure.

⚠ WHY IT IS KEPT RATHER THAN DELETED

   ``build_classifier()`` no longer returns it (``allow_heuristic=False`` by
   default), so it does not run for employees. It remains because:

   - it is the reference implementation of the ``DocumentClassifier`` Protocol,
     and Step 14's quality model needs a worked example of the same shape;
   - ``scripts/collect_classifier_features.py`` scores it against the corpus,
     which is how this conclusion was reached and how it will be re-checked;
   - its tests document what was tried and why it failed, which is the part
     most likely to be re-attempted by someone who has not seen these numbers.

⛔ WHAT THIS CLASSIFIER IS ALLOWED TO CLAIM

   Exactly one thing: **"this image contains no document at all."**

   It never returns AADHAAR_FRONT, AADHAAR_BACK, AADHAAR_PVC or OTHER_ID.
   Telling an Aadhaar from a PAN card, or a front from a back, needs a trained
   model. Anything else it is asked, it answers ``UNKNOWN`` — and ``UNKNOWN``
   changes nothing about how the pipeline behaves.

WHY THE CLAIM IS THIS NARROW — THE MEASUREMENT THAT DECIDED IT
--------------------------------------------------------------
The obvious heuristic is "documents are dense with edges — text, rules, borders
— so high edge density means a document." Measured on generated stand-ins::

    card with QR       edge density 0.052
    card without QR    edge density 0.042
    handwritten page   edge density 0.035
    ─────────────────────────────────────
    random noise       edge density 0.104   ← nearly 2x the card
    brick wall         edge density 0.104   ← nearly 2x the card

**A brick wall is more "document-like" than an Aadhaar card by that measure.**
High edge density means nothing at all; it is satisfied by any textured scene.

What survives is the other end. An image with essentially no edge structure, no
rectangular document boundary and no QR is not a document — no photograph of a
card produces that, whatever the lighting. So the low end is asserted and the
rest is ``UNKNOWN``.

⛔ WHAT REAL MEASUREMENT CORRECTED — 17 August 2026

   The thresholds above were originally set from GENERATED images, where
   non-documents measured exactly 0.0000 edge density and documents 0.035+. I
   asserted that no real photograph would ever produce 0.0000.

   **That was wrong.** Run against 22 real Aadhaar photographs::

       phone-a-dim          4 images   0.0000 / 0.0019 / 0.0096   ← REAL CARDS
       phone-b-good-light   2 images   0.0334 / 0.0335 / 0.0335
       phone-b-angled       6 images   0.0286 / 0.0344 / 0.0506
       phone-b-glare        4 images   0.0345 / 0.0451 / 0.0722
       phone-a-good-light   4 images   0.0807 / 0.1044 / 0.1232
       scanner              2 images   0.0807 / 0.1019 / 0.1232

   Three of the four ``phone-a-dim`` images sit AT OR BELOW the 0.005 floor.
   They are genuine Aadhaar cards. **Underexposure destroys edge structure**, so
   a dim photo of a real card is indistinguishable from a blank wall by edge
   density alone — the two classes overlap completely at the low end, which is
   the opposite of what the generated data implied.

   Those images escaped misclassification only because the QR/quad check runs
   first and happened to fire. That is luck, not margin.

⛔ THE FIX: EXPOSURE GATING

   ``NOT_A_DOCUMENT`` now additionally requires the frame to be adequately
   exposed. A dark frame with no edges is an EXPOSURE problem, and the standard
   "photograph it in good light" message is already the correct advice for it —
   so the classifier stays silent and lets that message stand.

   What remains claimable: a well-lit frame with no edges, no document boundary
   and no QR. That is a blank surface, and no exposure of a real card produces
   it.

⛔ THIS CANNOT REJECT ANYTHING

  A ``NOT_A_DOCUMENT`` prediction never becomes a verdict. It refines the
  message on a verification that has ALREADY failed deterministically. If the
  QR decodes and the signature verifies, the result is VERIFIED no matter what
  this file thinks it is looking at. See ``avs.pipeline`` and D128.
"""

from __future__ import annotations

import numpy as np

from avs.ai.classify.features import DocumentFeatures, extract_features
from avs.contracts import DocType, DocTypePrediction, ValidatedImage
from avs.logging import get_logger

__all__ = ["HeuristicClassifier"]

log = get_logger(__name__)

#: Below this, a WELL-EXPOSED frame has no structure in it at all.
#:
#: ⛔ Only meaningful together with MIN_MEAN_BRIGHTNESS. Real dim Aadhaar photos
#:    measured 0.0000-0.0096 — below this floor — so on its own this test would
#:    call genuine cards blank surfaces. See the module docstring.
EDGE_DENSITY_FLOOR = 0.005

#: Mean luminance (0-255) below which the frame is treated as underexposed and
#: the classifier declines to judge it.
#:
#: ⚠ Set to a plainly dark value rather than tuned. The measured `phone-a-dim`
#:   cards are the only real evidence available about underexposure, and four
#:   images cannot support a precise cutoff. What this must do is guarantee that
#:   an underexposed card is never called a non-document; being generous costs
#:   only some UNKNOWNs on dim blank walls, which change nothing.
MIN_MEAN_BRIGHTNESS = 60.0

#: Confidence reported when the floor test fires. Not 1.0 — this is an advisory
#: signal from a heuristic, and a component that cannot be wrong is a component
#: nobody checks.
NOT_A_DOCUMENT_CONFIDENCE = 0.80


class HeuristicClassifier:
    """Implements the ``DocumentClassifier`` Protocol without a model.

    Ships as the interim classifier, exactly as the Step 11 capture thresholds
    ship as the interim version of the Step 14 quality model. It is honest about
    its narrowness: it answers one question, and returns ``UNKNOWN`` for every
    other question it is asked.
    """

    name = "heuristic-v1"

    def classify(self, image: ValidatedImage) -> DocTypePrediction:
        """Classify an image. Never raises.

        ⛔ An advisory component that can throw is not advisory — it is a
           dependency with extra steps (D120). Every failure here becomes
           ``UNKNOWN``, which the pipeline treats as "no opinion".
        """
        try:
            decoded = self._decode(image)
            if decoded is None:
                return self._unknown("image could not be decoded for classification")
            features = extract_features(decoded)
        except BaseException as exc:
            log.warning("ai.classify.failed", error=type(exc).__name__)
            return self._unknown(f"{type(exc).__name__}")

        return self.classify_features(features)

    def classify_features(self, features: DocumentFeatures) -> DocTypePrediction:
        """The decision, separated from image handling so it can be tested on
        numbers alone — including numbers measured from real cards on a machine
        this code never sees."""

        # ⛔ Order matters. A QR or a document quad is POSITIVE evidence that
        #    something document-shaped is present, and it outranks the absence
        #    tests below. Running the floor test first would let a dark photo of
        #    a real card be called "not a document" when we can see its QR.
        if features.has_qr or features.has_document_quad:
            return DocTypePrediction(
                doc_type=DocType.UNKNOWN,
                confidence=0.0,
                model_version=self.name,
            )

        # ⛔ Underexposed. A dim photo of a REAL card measures 0.0000 edge
        #    density — the measurement that corrected this file. The existing
        #    "photograph it in good light" message is already correct advice
        #    here, so say nothing and let it stand.
        if features.mean_brightness < MIN_MEAN_BRIGHTNESS:
            return DocTypePrediction(
                doc_type=DocType.UNKNOWN,
                confidence=0.0,
                model_version=self.name,
            )

        if features.edge_density < EDGE_DENSITY_FLOOR:
            return DocTypePrediction(
                doc_type=DocType.NOT_A_DOCUMENT,
                confidence=NOT_A_DOCUMENT_CONFIDENCE,
                model_version=self.name,
            )

        # ⚠ Everything else. A textured scene, a PAN card, an Aadhaar front, an
        #   Aadhaar back — this classifier cannot tell them apart and does not
        #   pretend to. Distinguishing them is what the trained model is for.
        return DocTypePrediction(
            doc_type=DocType.UNKNOWN,
            confidence=0.0,
            model_version=self.name,
        )

    # ------------------------------------------------------------------ #

    def _unknown(self, reason: str) -> DocTypePrediction:
        log.debug("ai.classify.unknown", reason=reason)
        return DocTypePrediction(
            doc_type=DocType.UNKNOWN,
            confidence=0.0,
            model_version=self.name,
        )

    @staticmethod
    def _decode(image: ValidatedImage) -> np.ndarray | None:
        import cv2

        buffer = np.frombuffer(image.data, dtype=np.uint8)
        decoded = cv2.imdecode(buffer, cv2.IMREAD_COLOR)
        if decoded is None or decoded.size == 0:
            return None
        return decoded
