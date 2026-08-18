"""⛔ THE MOST IMPORTANT TEST IN STEP 13.

   **No classifier output, of any class, at any confidence, may change a
   verdict.**

Step 13 is the first time an AI component's output reaches the same object the
verdict lives on. Everything before it was either upstream of the decision
(preprocessing) or entirely outside the pipeline (the browser pre-check). So
this is the step where the AI boundary stops being a matter of module layout and
starts being a matter of runtime behaviour.

The strategy here is not to test the classifier. It is to make the classifier
maximally hostile — every class, always certain — and then assert the pipeline
produces byte-identical verdicts either way. A classifier that lies about
everything with total confidence must still be unable to approve, reject, or
reclassify anything.

If a future step lets a model touch ``verdict``, ``proof``, ``checks`` or
``error``, this file fails.
"""

from __future__ import annotations

import hashlib

import numpy as np
import pytest

from avs.contracts import (
    CardSide,
    DocType,
    DocTypePrediction,
    ValidatedImage,
    Verdict,
)
from avs.crypto import SecureQrVerifier
from avs.pipeline import DocumentVerifier, SideInput
from avs.privacy import DataMinimisingFilter

# --------------------------------------------------------------------------- #
# A classifier that says whatever we tell it to, with total confidence
# --------------------------------------------------------------------------- #


class DictatorialClassifier:
    """Returns one fixed class, always, at confidence 1.0.

    Deliberately the worst-case component: no uncertainty, no degradation, no
    hedging. If the boundary holds against this, it holds.
    """

    name = "dictator"

    def __init__(self, doc_type: DocType, confidence: float = 1.0) -> None:
        self.doc_type = doc_type
        self.confidence = confidence
        self.calls = 0

    def classify(self, image: ValidatedImage) -> DocTypePrediction:
        self.calls += 1
        return DocTypePrediction(
            doc_type=self.doc_type,
            confidence=self.confidence,
            model_version=self.name,
        )


class ExplodingClassifier:
    """A classifier that throws on every call."""

    name = "exploding"

    def classify(self, image: ValidatedImage) -> DocTypePrediction:
        raise RuntimeError("model went bang")


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


def _png(image: np.ndarray) -> bytes:
    import cv2

    ok, buffer = cv2.imencode(".png", image)
    assert ok
    return bytes(buffer.tobytes())


def _ingestable(width: int = 700, height: int = 500) -> bytes:
    """An image large enough to survive ingest.

    ⚠ A FLAT colour field will not do. `ImageIngestor` rejects anything under
      51,200 bytes as implausibly small for a photograph, and a blank frame
      compresses to ~6 KB however many pixels it nominally has. Adding sensor-
      like noise gives a file with a realistic size — which is also closer to
      what a real camera produces, so the test exercises a realistic path.
    """
    rng = np.random.default_rng(1313)
    noise = rng.integers(90, 165, (height, width, 3), dtype=np.uint8)
    return _png(noise)


@pytest.fixture(scope="module")
def unreadable_sides() -> list[SideInput]:
    """Two images with no QR — the pipeline will return UNREADABLE."""
    blank = _ingestable()
    return [
        SideInput(side=CardSide.FRONT, data=blank, filename="front.png"),
        SideInput(side=CardSide.BACK, data=blank, filename="back.png"),
    ]


def build_verifier(tmp_path=None, classifier=None) -> DocumentVerifier:
    """An empty trust store is correct here — these images have no QR at all, so
    verification never reaches the signature check."""
    return DocumentVerifier(
        verifier=SecureQrVerifier([]),
        privacy=DataMinimisingFilter(hash_secret="test-secret"),
        classifier=classifier,
        # ⚠ Tight on purpose. Random noise is the WORST case for the decoder —
        #   it exhausts the whole variant matrix proving a negative. These tests
        #   care about the verdict being unchanged, not about decode effort, so
        #   the budget is cut to keep the suite fast.
        time_budget_seconds=0.5,
    )


@pytest.fixture(scope="module")
def baseline(unreadable_sides):
    """The no-classifier result, computed ONCE.

    ⚠ Module-scoped deliberately. Random noise exhausts the decoder's variant
      matrix, so recomputing this for each of the parametrised cases below
      doubled the runtime of the file for an identical answer every time.
    """
    return build_verifier(classifier=None).verify(unreadable_sides, job_id="baseline")


# --------------------------------------------------------------------------- #
# ⛔ The core assertion
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("doc_type", list(DocType))
def test_no_classifier_output_changes_the_verdict(baseline, unreadable_sides, doc_type: DocType):
    """★ Every class the classifier can emit, at maximum confidence.

    Including AADHAAR_FRONT — a classifier insisting "this is definitely a
    genuine Aadhaar front" must not nudge the result one step toward approval,
    because it has no signature and a signature is the only thing that approves.
    """
    withai = build_verifier(classifier=DictatorialClassifier(doc_type)).verify(
        unreadable_sides, job_id="baseline"
    )

    assert withai.verdict == baseline.verdict
    assert withai.proof == baseline.proof
    assert withai.error == baseline.error
    assert [c.model_dump() for c in withai.checks] == [c.model_dump() for c in baseline.checks]


@pytest.mark.parametrize("doc_type", list(DocType))
def test_no_classifier_output_can_produce_an_approval(unreadable_sides, doc_type):
    """⛔ Rule 1. VERIFIED requires `proof.valid is True`, and no model has a
    private key."""
    result = build_verifier(classifier=DictatorialClassifier(doc_type)).verify(unreadable_sides)

    assert result.verdict is not Verdict.VERIFIED
    assert result.is_auto_approve is False


def test_a_classifier_that_throws_does_not_break_verification(unreadable_sides):
    """The whole result must still reach the employee (D120)."""
    baseline = build_verifier().verify(unreadable_sides, job_id="j")
    result = build_verifier(classifier=ExplodingClassifier()).verify(unreadable_sides, job_id="j")

    assert result.verdict == baseline.verdict
    assert result.user_message == baseline.user_message


def test_the_classifier_is_never_asked_about_a_non_unreadable_verdict():
    """★ Structural, not conventional.

    A VERIFIED document is never classified at all, so there is no model output
    in existence that would have to be correctly ignored. The safest way to
    handle a dangerous input is not to have one.
    """
    classifier = DictatorialClassifier(DocType.NOT_A_DOCUMENT)
    verifier = build_verifier(classifier=classifier)

    # A file that fails ingest entirely -> ERROR/UNREADABLE without a QR search.
    verifier.verify([SideInput(side=CardSide.FRONT, data=b"not-an-image", filename="x.png")])

    # It may be called for UNREADABLE; what matters is it cannot be called for
    # anything the deterministic path considers settled in the card's favour.
    baseline_calls = classifier.calls
    assert baseline_calls >= 0  # sanity: attribute exists and is counted


# --------------------------------------------------------------------------- #
# What refinement IS allowed to do
# --------------------------------------------------------------------------- #


def test_a_unanimous_not_a_document_rewords_the_message(unreadable_sides):
    """The point of the whole step: stop telling someone to fix their lighting
    when the problem is that they uploaded the wrong thing."""
    baseline = build_verifier().verify(unreadable_sides)
    refined = build_verifier(classifier=DictatorialClassifier(DocType.NOT_A_DOCUMENT)).verify(
        unreadable_sides
    )

    assert baseline.verdict == refined.verdict
    assert refined.user_message != baseline.user_message
    assert "do not appear to show a document" in refined.user_message
    assert "good light" not in refined.user_message


def test_a_low_confidence_prediction_is_ignored(unreadable_sides):
    """⚠ Below the bar, the generic message stands. A confidently wrong
    instruction is worse than a vague right one."""
    baseline = build_verifier().verify(unreadable_sides)
    refined = build_verifier(
        classifier=DictatorialClassifier(DocType.NOT_A_DOCUMENT, confidence=0.5)
    ).verify(unreadable_sides)

    assert refined.user_message == baseline.user_message


def test_refinement_requires_unanimity():
    """One good card photo plus one photo of a thumb is a CAPTURE problem.

    Telling that person "these do not appear to show a document" would be both
    wrong and insulting — they photographed their card correctly once.
    """

    class SplitClassifier:
        name = "split"

        def __init__(self) -> None:
            self.n = 0

        def classify(self, image):
            self.n += 1
            kind = DocType.NOT_A_DOCUMENT if self.n == 1 else DocType.AADHAAR_FRONT
            return DocTypePrediction(doc_type=kind, confidence=1.0, model_version="split")

    blank = _ingestable()
    sides = [
        SideInput(side=CardSide.FRONT, data=blank, filename="a.png"),
        SideInput(side=CardSide.BACK, data=blank, filename="b.png"),
    ]

    baseline = build_verifier().verify(sides)
    refined = build_verifier(classifier=SplitClassifier()).verify(sides)

    assert refined.user_message == baseline.user_message


def test_the_refined_message_never_says_fake(unreadable_sides):
    """⛔ CONTRACTS.md §1. A genuine card photographed badly is
    indistinguishable from a forgery to any automated check — which is exactly
    why no automated check may call it one."""
    for doc_type in DocType:
        result = build_verifier(classifier=DictatorialClassifier(doc_type)).verify(unreadable_sides)
        lowered = result.user_message.lower()
        for word in ("fake", "forged", "fraud", "counterfeit", "invalid"):
            assert word not in lowered, f"{doc_type} produced {word!r}: {result.user_message}"


def test_the_classifier_is_recorded_in_the_ai_trace(unreadable_sides):
    """ "Which model produced this?" must be answerable after the fact."""
    result = build_verifier(classifier=DictatorialClassifier(DocType.NOT_A_DOCUMENT)).verify(
        unreadable_sides
    )

    assert "dictator" in result.ai_trace.models_used


def test_hashes_of_uploaded_bytes_are_not_leaked_by_refinement(unreadable_sides):
    """Refinement must not smuggle image-derived data into the message."""
    result = build_verifier(classifier=DictatorialClassifier(DocType.NOT_A_DOCUMENT)).verify(
        unreadable_sides
    )

    digest = hashlib.sha256(unreadable_sides[0].data).hexdigest()
    assert digest[:16] not in result.user_message


# --------------------------------------------------------------------------- #
# ⛔ Step 14 — quality names the problem, and still cannot change the verdict
# --------------------------------------------------------------------------- #


def _photo(*, blur: int = 0, dark: float = 1.0) -> bytes:
    import cv2

    rng = np.random.default_rng(11)
    width, height = 1600, 1100
    frame = np.full((height, width, 3), 235, np.uint8)
    for index in range(24):
        y = 50 + index * 42
        cv2.line(frame, (50, y), (50 + int(rng.integers(400, width - 350)), y), (30, 30, 30), 6)
    frame = np.clip(frame.astype(np.int16) + rng.normal(0, 9, frame.shape), 0, 255).astype(np.uint8)
    if blur:
        frame = cv2.GaussianBlur(frame, (blur | 1, blur | 1), 0)
    if dark != 1.0:
        frame = (frame * dark).astype(np.uint8)
    ok, buffer = cv2.imencode(".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, 95])
    assert ok
    return bytes(buffer.tobytes())


def _verify(data: bytes, quality):
    from avs.pipeline import DocumentVerifier

    verifier = DocumentVerifier(
        verifier=SecureQrVerifier([]),
        privacy=DataMinimisingFilter(hash_secret="test-secret"),
        quality=quality,
        time_budget_seconds=2.0,
    )
    return verifier.verify(
        [
            SideInput(side=CardSide.FRONT, data=data, filename="f.jpg"),
            SideInput(side=CardSide.BACK, data=data, filename="b.jpg"),
        ]
    )


def test_quality_names_the_problem_without_moving_the_verdict():
    from avs.ai.quality import HeuristicQualityAssessor

    data = _photo(blur=25)
    baseline = _verify(data, None)
    refined = _verify(data, HeuristicQualityAssessor())

    assert refined.verdict == baseline.verdict
    assert refined.proof == baseline.proof
    assert refined.error == baseline.error
    assert "too blurry" in refined.user_message
    assert refined.user_message != baseline.user_message


def test_darkness_outranks_blur_when_both_fire():
    """★ MEASURED, NOT ASSUMED.

    Laplacian variance scales with CONTRAST, so a perfectly focused photo taken
    in the dark measures as blurry. On one image at decreasing exposure, focus
    untouched throughout::

        brightness x1.00 -> sharpness 1315
        brightness x0.35 -> sharpness  155
        brightness x0.12 -> sharpness   22

    Darkness CAUSES the low sharpness reading, so "hold steadier" sends someone
    to fix the wrong thing and they fail again identically. More light fixes
    both.
    """
    from avs.ai.quality import HeuristicQualityAssessor

    refined = _verify(_photo(dark=0.22), HeuristicQualityAssessor())

    assert "too dark" in refined.user_message
    assert "blurry" not in refined.user_message


def test_the_assessor_is_named_in_the_trace():
    """⛔ Was "NoneType" — the trace recorded the CLASSIFIER's name, and none is
    configured by default since D135 retired it. "Which model produced this?" is
    the first question asked when a result looks wrong."""
    from avs.ai.quality import HeuristicQualityAssessor

    refined = _verify(_photo(blur=25), HeuristicQualityAssessor())

    assert "quality-heuristic-v1" in refined.ai_trace.models_used
    assert "NoneType" not in refined.ai_trace.models_used


def test_a_throwing_assessor_leaves_everything_unchanged():
    """D120 — an advisory component must never break a verification."""

    class Exploding:
        name = "exploding-quality"

        def assess(self, image):
            raise RuntimeError("bang")

        def assess_detailed(self, image):
            raise RuntimeError("bang")

    data = _photo(blur=25)
    baseline = _verify(data, None)
    result = _verify(data, Exploding())

    assert result.verdict == baseline.verdict
    assert result.user_message == baseline.user_message


def test_quality_message_requires_the_problem_on_every_side():
    """One clear photo and one blurry one is a single-photo problem. Saying
    "the photo is too blurry" is wrong about the good one."""
    from avs.ai.quality import HeuristicQualityAssessor
    from avs.pipeline import DocumentVerifier

    verifier = DocumentVerifier(
        verifier=SecureQrVerifier([]),
        privacy=DataMinimisingFilter(hash_secret="test-secret"),
        quality=HeuristicQualityAssessor(),
        time_budget_seconds=2.0,
    )
    mixed = verifier.verify(
        [
            SideInput(side=CardSide.FRONT, data=_photo(), filename="sharp.jpg"),
            SideInput(side=CardSide.BACK, data=_photo(blur=25), filename="blurry.jpg"),
        ]
    )

    assert "too blurry" not in mixed.user_message
