"""Document classifier — Step 13.

Two things are tested here, and the second matters more than the first:

1. The classifier does what it claims.
2. **The classifier does not claim more than it can support.**

(2) is unusual as a test target, and it is here because of what Step 7.5 cost.
A fixture built from the same understanding as the code proves only that the two
agree. So the tests below deliberately try to catch the classifier overclaiming
— asserting that a textured non-document, an unusual aspect ratio and a blurry
card all come back UNKNOWN rather than confidently wrong.
"""

from __future__ import annotations

import hashlib

import numpy as np
import pytest

from avs.ai.classify import HeuristicClassifier, build_classifier
from avs.ai.classify.features import extract_features
from avs.ai.classify.heuristic import MIN_MEAN_BRIGHTNESS
from avs.ai.classify.onnx import CLASS_ORDER, MODEL_NAME, OnnxDocumentClassifier, _softmax
from avs.ai.modelmgr import ModelRegistry, ModelRunner, ModelSpec
from avs.contracts import DocType, ValidatedImage

# --------------------------------------------------------------------------- #
# Image builders — shapes, never real cards
# --------------------------------------------------------------------------- #


def as_validated(image: np.ndarray) -> ValidatedImage:
    import cv2

    ok, buffer = cv2.imencode(".png", image)
    assert ok
    data = bytes(buffer.tobytes())
    height, width = image.shape[:2]
    return ValidatedImage(
        data=data,
        mime_type="image/png",
        width=width,
        height=height,
        size_bytes=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
    )


def card_like(*, with_qr: bool = True) -> np.ndarray:
    """A document-shaped image: light card on a dark ground, dense text lines."""
    import cv2

    rng = np.random.default_rng(13)
    width, height = 1600, 1000
    frame = np.full((height + 300, width + 300, 3), 70, np.uint8)
    card = np.full((height, width, 3), 245, np.uint8)

    for index in range(28):
        y = 90 + index * 30
        cv2.line(card, (60, y), (60 + int(rng.integers(300, width - 400)), y), (30, 30, 30), 6)

    if with_qr:
        module = 12
        grid = (rng.random((21, 21)) > 0.5).astype(np.uint8) * 255
        for cy, cx in [(0, 0), (0, 14), (14, 0)]:
            grid[cy : cy + 7, cx : cx + 7] = 0
            grid[cy + 1 : cy + 6, cx + 1 : cx + 6] = 255
            grid[cy + 2 : cy + 5, cx + 2 : cx + 5] = 0
        qr = cv2.cvtColor(
            cv2.resize(grid, (21 * module, 21 * module), interpolation=cv2.INTER_NEAREST),
            cv2.COLOR_GRAY2BGR,
        )
        card[height - 21 * module - 50 : height - 50, width - 21 * module - 50 : width - 50] = qr

    frame[150 : 150 + height, 150 : 150 + width] = card
    return frame


def brick_wall() -> np.ndarray:
    """★ The adversarial case. High edge density, definitely not a document."""
    import cv2

    rng = np.random.default_rng(7)
    frame = np.full((1200, 1600, 3), 150, np.uint8)
    for y in range(0, 1200, 40):
        cv2.line(frame, (0, y), (1600, y), (90, 90, 90), 3)
    for x in range(0, 1600, 90):
        cv2.line(frame, (x, 0), (x, 1200), (90, 90, 90), 3)
    return np.clip(frame.astype(np.int16) + rng.normal(0, 12, frame.shape), 0, 255).astype(np.uint8)


# --------------------------------------------------------------------------- #
# ⛔ What the heuristic may claim
# --------------------------------------------------------------------------- #


def test_a_dark_frame_is_unknown_not_a_verdict_about_documents():
    """★ CORRECTED BY REAL DATA — 17 Aug 2026.

    This originally asserted NOT_A_DOCUMENT. Then 22 real Aadhaar photographs
    were measured and the `phone-a-dim` folder came back at 0.0000-0.0096 edge
    density — genuine cards, indistinguishable from a blank frame.

    Underexposure destroys edge structure. So a dark frame is an EXPOSURE
    problem, and "photograph it in good light" (the message already shown) is
    the correct advice. The classifier must stay out of it.
    """
    classifier = HeuristicClassifier()
    result = classifier.classify(as_validated(np.full((900, 900, 3), 8, np.uint8)))

    assert result.doc_type is DocType.UNKNOWN


def test_a_well_lit_featureless_frame_is_not_a_document():
    """What survives the correction: a BRIGHT blank surface. No exposure of a
    real card produces this."""
    classifier = HeuristicClassifier()
    result = classifier.classify(as_validated(np.full((900, 900, 3), 200, np.uint8)))

    assert result.doc_type is DocType.NOT_A_DOCUMENT


def test_a_dim_real_card_is_never_called_a_non_document():
    """⛔ THE REGRESSION FROM DHEERAJ'S CORPUS.

    Modelled on the measured `phone-a-dim` images: a real card, underexposed,
    edge density at the floor, and — the dangerous part — WITHOUT the QR or
    document quad being detected. In the real corpus those images were saved
    only because the QR check happened to fire. This asserts they are safe even
    when it does not.
    """
    from avs.ai.classify.features import DocumentFeatures

    dim_card = DocumentFeatures(
        width=3000,
        height=4000,
        aspect_ratio=1.33,
        has_document_quad=False,  # the luck that saved them, removed
        quad_area_fraction=0.0,
        has_qr=False,
        qr_area_fraction=0.0,
        edge_density=0.0000,  # measured on a REAL card
        saturation_mean=20.0,
        dark_fraction=0.65,
        mean_brightness=35.0,  # underexposed
        blur=15.0,
    )
    result = HeuristicClassifier().classify_features(dim_card)

    assert result.doc_type is DocType.UNKNOWN, (
        "A dim photo of a real Aadhaar card must never be called a non-document"
    )


@pytest.mark.parametrize("with_qr", [True, False])
def test_a_card_is_never_called_not_a_document(with_qr: bool):
    """⛔ The expensive error. Telling someone their real card is not a document
    is far worse than saying nothing, so it must not happen for any card-shaped
    input."""
    result = HeuristicClassifier().classify(as_validated(card_like(with_qr=with_qr)))

    assert result.doc_type is not DocType.NOT_A_DOCUMENT


def test_a_textured_non_document_is_unknown_not_a_guess():
    """★ THE TEST THAT SET THE DESIGN.

    Measured: a brick wall scores edge density 0.104, a real card 0.042. The
    wall is *twice* as "document-like" on the obvious feature. So the heuristic
    must not use high edge density as evidence of anything, and must answer
    UNKNOWN here rather than guessing in either direction.
    """
    result = HeuristicClassifier().classify(as_validated(brick_wall()))

    assert result.doc_type is DocType.UNKNOWN
    assert result.confidence == 0.0


def test_the_heuristic_never_claims_a_specific_aadhaar_class():
    """⛔ It has no way to tell a front from a back or an Aadhaar from a PAN.

    If a future change makes it emit AADHAAR_FRONT, that claim is unbacked and
    this fails.
    """
    classifier = HeuristicClassifier()
    specific = {DocType.AADHAAR_FRONT, DocType.AADHAAR_BACK, DocType.AADHAAR_PVC, DocType.OTHER_ID}

    for image in (card_like(with_qr=True), card_like(with_qr=False), brick_wall()):
        assert classifier.classify(as_validated(image)).doc_type not in specific


def test_positive_evidence_outranks_the_absence_tests():
    """A dark photo of a real card must not be called "not a document" when its
    QR is visible. Order of checks, asserted."""
    from avs.ai.classify.features import DocumentFeatures

    features = DocumentFeatures(
        width=1600,
        height=1000,
        aspect_ratio=1.6,
        has_document_quad=False,
        quad_area_fraction=0.0,
        has_qr=True,  # we can SEE a QR
        qr_area_fraction=0.05,
        edge_density=0.0,  # ...and no other structure at all
        saturation_mean=0.0,
        dark_fraction=0.99,  # ...in a very dark frame
        mean_brightness=12.0,
        blur=0.0,
    )
    result = HeuristicClassifier().classify_features(features)

    assert result.doc_type is DocType.UNKNOWN


def test_the_edge_floor_is_never_used_without_the_exposure_gate():
    """⛔ The two thresholds are only safe TOGETHER.

    Real measurement: dim Aadhaar cards produce 0.0000-0.0096 edge density,
    straddling the floor. Edge density alone therefore cannot separate a card
    from a blank wall — only "no edges AND well exposed" can. If a future change
    drops the brightness gate, this fails.
    """
    import inspect

    from avs.ai.classify import heuristic

    source = inspect.getsource(heuristic.HeuristicClassifier.classify_features)
    assert "MIN_MEAN_BRIGHTNESS" in source, "the exposure gate was removed"
    assert source.index("MIN_MEAN_BRIGHTNESS") < source.index("EDGE_DENSITY_FLOOR"), (
        "the exposure gate must be checked BEFORE the edge floor"
    )
    assert MIN_MEAN_BRIGHTNESS > 0


def test_classification_never_raises_on_junk_bytes():
    junk = ValidatedImage(
        data=b"this is not an image at all",
        mime_type="image/png",
        width=10,
        height=10,
        size_bytes=27,
        sha256=hashlib.sha256(b"x").hexdigest(),
    )
    assert HeuristicClassifier().classify(junk).doc_type is DocType.UNKNOWN


def test_features_never_raise_on_an_empty_array():
    features = extract_features(np.zeros((0, 0, 3), np.uint8))
    assert features.edge_density == 0.0


def test_feature_rows_carry_no_content():
    """⛔ The privacy property that lets features leave a machine holding real
    cards. Every value must be a number."""
    row = extract_features(card_like()).as_row()

    assert all(isinstance(value, (int, float)) for value in row.values())
    assert not {"text", "name", "aadhaar", "payload", "uid"} & set(row)


# --------------------------------------------------------------------------- #
# ONNX backend — degradation and the class-order contract
# --------------------------------------------------------------------------- #


def _onnx_with(backend, tmp_path, monkeypatch) -> OnnxDocumentClassifier:
    from avs.ai.modelmgr.runtime import InferenceSession

    spec = ModelSpec(
        name=MODEL_NAME,
        version="1.0.0",
        filename=f"{MODEL_NAME}.onnx",
        sha256="a" * 64,
    )
    runner = ModelRunner(ModelRegistry(tmp_path, {MODEL_NAME: spec}))
    monkeypatch.setattr(runner, "_load", lambda _name: InferenceSession(spec, backend))
    return OnnxDocumentClassifier(runner)


def test_an_absent_model_yields_unknown(tmp_path):
    from avs.ai.modelmgr import load_registry

    classifier = OnnxDocumentClassifier(ModelRunner(load_registry(tmp_path)))
    assert classifier.classify(as_validated(card_like())).doc_type is DocType.UNKNOWN


def test_a_confident_model_output_is_used(tmp_path, monkeypatch):
    class Confident:
        def run(self, _outputs, _inputs):
            return [np.array([[20.0, 0.0, 0.0, 0.0, 0.0]])]  # AADHAAR_FRONT

    classifier = _onnx_with(Confident(), tmp_path, monkeypatch)
    result = classifier.classify(as_validated(card_like()))

    assert result.doc_type is DocType.AADHAAR_FRONT
    assert result.confidence > 0.99


def test_an_unconvinced_model_yields_unknown(tmp_path, monkeypatch):
    class Undecided:
        def run(self, _outputs, _inputs):
            return [np.array([[1.0, 1.0, 1.0, 1.0, 1.0]])]  # uniform -> 0.2 each

    classifier = _onnx_with(Undecided(), tmp_path, monkeypatch)
    assert classifier.classify(as_validated(card_like())).doc_type is DocType.UNKNOWN


def test_a_wrong_output_width_is_refused(tmp_path, monkeypatch):
    """⛔ A model retrained with different classes must not be reinterpreted
    against the old order — that produces confident nonsense, not an error."""

    class WrongShape:
        def run(self, _outputs, _inputs):
            return [np.array([[1.0, 2.0, 3.0]])]  # 3 classes, not 5

    classifier = _onnx_with(WrongShape(), tmp_path, monkeypatch)
    assert classifier.classify(as_validated(card_like())).doc_type is DocType.UNKNOWN


def test_nan_output_is_refused(tmp_path, monkeypatch):
    """NaN propagates silently through argmax and comparison."""

    class NotANumber:
        def run(self, _outputs, _inputs):
            return [np.array([[np.nan] * 5])]

    classifier = _onnx_with(NotANumber(), tmp_path, monkeypatch)
    assert classifier.classify(as_validated(card_like())).doc_type is DocType.UNKNOWN


def test_a_throwing_model_yields_unknown(tmp_path, monkeypatch):
    class Exploding:
        def run(self, _outputs, _inputs):
            raise RuntimeError("bang")

    classifier = _onnx_with(Exploding(), tmp_path, monkeypatch)
    assert classifier.classify(as_validated(card_like())).doc_type is DocType.UNKNOWN


def test_class_order_matches_the_contract():
    """⛔ CLASS_ORDER is part of the model contract. Changing it without
    retraining silently relabels every prediction."""
    assert CLASS_ORDER == (
        DocType.AADHAAR_FRONT,
        DocType.AADHAAR_BACK,
        DocType.AADHAAR_PVC,
        DocType.OTHER_ID,
        DocType.NOT_A_DOCUMENT,
    )
    assert DocType.UNKNOWN not in CLASS_ORDER, "UNKNOWN is our word for 'no answer', not a class"


def test_softmax_survives_logits_that_would_overflow():
    """⚠ exp(710) is inf in float64, which makes every probability NaN. Vision
    models routinely emit logits that large."""
    probabilities = _softmax(np.array([1000.0, 999.0, 0.0, 0.0, 0.0]))

    assert np.all(np.isfinite(probabilities))
    assert pytest.approx(1.0) == float(np.sum(probabilities))


# --------------------------------------------------------------------------- #
# Backend selection
# --------------------------------------------------------------------------- #


def test_build_classifier_does_not_return_the_heuristic_by_default(tmp_path):
    """⛔ RETIRED BY MEASUREMENT — 17 Aug 2026.

    The heuristic caught 0 of 19 real wrong-uploads. Its feature ranges overlap
    the document ranges 100% on edge density, so no threshold separates them.

    It must not run for employees. If a future change flips the default back on,
    this fails — and whoever flips it should first re-run
    `scripts/collect_classifier_features.py` and get a non-zero recall.
    """
    assert build_classifier(str(tmp_path)) is None


def test_the_heuristic_is_still_available_for_diagnostics(tmp_path):
    """Retired, not deleted. `avs classify` and the corpus collector opt in
    explicitly — that tooling is how the retirement was decided and how it
    would be revisited."""
    assert isinstance(build_classifier(str(tmp_path), allow_heuristic=True), HeuristicClassifier)


def test_build_classifier_survives_a_broken_manifest(tmp_path):
    """A malformed models.json must not stop classification, let alone
    verification."""
    (tmp_path / "models.json").write_text("{ not json", encoding="utf-8")

    assert build_classifier(str(tmp_path)) is None
    assert isinstance(build_classifier(str(tmp_path), allow_heuristic=True), HeuristicClassifier)


def test_build_classifier_can_return_none(tmp_path):
    assert build_classifier(str(tmp_path), allow_heuristic=False) is None


def test_the_measured_overlap_is_recorded_where_it_will_be_read():
    """★ The evidence must live next to the code it condemns.

    A decision documented only in a commit message is a decision nobody finds.
    Someone re-enabling the heuristic will open `heuristic.py` first, so the
    numbers that retired it are in its module docstring.
    """
    from avs.ai.classify import heuristic

    doc = heuristic.__doc__ or ""
    assert "0 of 19" in doc, "the measured recall must be stated"
    assert "100% overlap" in doc or "100% OVERLAP" in doc.upper(), (
        "the reason tuning cannot fix it must be stated"
    )
    assert "RETIRED" in doc


# --------------------------------------------------------------------------- #
# CLI — the failure a documented placeholder caused
# --------------------------------------------------------------------------- #


def _write_image(path, value: int) -> None:
    import cv2

    path.parent.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(5)
    frame = np.clip(rng.normal(value, 6, (600, 800, 3)), 0, 255).astype(np.uint8)
    cv2.imwrite(str(path), frame)


def test_classify_accepts_a_folder(tmp_path):
    """⛔ THE FIX FOR A REAL FAILURE.

    `avs classify` originally demanded one file path, so documenting it required
    a placeholder filename. The placeholder got pasted verbatim, PowerShell split
    it on its spaces, and typer reported "unexpected extra argument" — an error
    that says nothing about the real problem.

    Accepting a folder removes the need for a filename entirely: there is
    nothing to guess and nothing to paste wrongly.
    """
    from typer.testing import CliRunner

    from avs.cli import app

    _write_image(tmp_path / "a.jpg", 210)
    _write_image(tmp_path / "b.jpg", 30)

    result = CliRunner().invoke(app, ["classify", str(tmp_path)])

    assert result.exit_code == 0
    assert "a.jpg" in result.stdout
    assert "b.jpg" in result.stdout


def test_classify_names_a_pasted_placeholder(tmp_path):
    """An error must say what to do next, not merely that something is wrong."""
    from typer.testing import CliRunner

    from avs.cli import app

    result = CliRunner().invoke(app, ["classify", str(tmp_path / "<pick")])

    assert result.exit_code == 2
    assert "placeholder" in result.stdout
    assert "FOLDER" in result.stdout


def test_classify_skips_non_images_inside_a_folder(tmp_path):
    """Corpus folders routinely hold stray notes and thumbnails. One of them
    must not abort the run."""
    from typer.testing import CliRunner

    from avs.cli import app

    _write_image(tmp_path / "a.jpg", 210)
    (tmp_path / "notes.txt").write_text("not an image", encoding="utf-8")

    result = CliRunner().invoke(app, ["classify", str(tmp_path)])

    assert result.exit_code == 0
    assert "a.jpg" in result.stdout


def test_classify_still_accepts_a_single_file(tmp_path):
    from typer.testing import CliRunner

    from avs.cli import app

    _write_image(tmp_path / "one.jpg", 210)
    result = CliRunner().invoke(app, ["classify", str(tmp_path / "one.jpg")])

    assert result.exit_code == 0
    assert "Measured features" in result.stdout  # full table for a single image
