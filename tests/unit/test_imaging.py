"""Image preprocessing tests — Step 4.

Decode rate is the project's primary metric, and this is the module that moves
it. These tests verify three things:

1. Every operation preserves what a QR decoder needs — module edges, dimensions
   where they matter, and lossless encoding.
2. Generation is genuinely lazy and cheapest-first, so a good capture costs one
   variant rather than twenty-three.
3. The Step 14 and Step 15 seams behave correctly when supplied and are
   invisible when absent.
"""

from __future__ import annotations

import io
import itertools
import os

import cv2
import numpy as np
import pytest
from PIL import Image

from avs.contracts import ImageVariant, QrRegion, QualityScores
from avs.imaging import (
    STRATEGIES,
    ImagingError,
    PreprocessingVariantGenerator,
    Problem,
    ops,
    problems_from_quality,
    select_strategies,
)
from avs.ingest import ImageIngestor
from tests.fixtures.images import make_image_bytes


@pytest.fixture
def photo():
    """A validated image, as ``ingest/`` would hand it over."""
    return ImageIngestor().ingest(make_image_bytes(width=800, height=600))


@pytest.fixture
def generator() -> PreprocessingVariantGenerator:
    return PreprocessingVariantGenerator()


def _array(width: int = 400, height: int = 300, *, noise: bool = True) -> np.ndarray:
    if noise:
        flat = np.frombuffer(os.urandom(width * height * 3), dtype=np.uint8)
        return flat.reshape(height, width, 3).copy()
    return np.full((height, width, 3), 128, dtype=np.uint8)


# --------------------------------------------------------------------------- #
# Operations
# --------------------------------------------------------------------------- #


class TestOperations:
    def test_grayscale_collapses_channels(self) -> None:
        assert ops.to_grayscale(_array()).ndim == 2

    def test_grayscale_is_idempotent(self) -> None:
        gray = ops.to_grayscale(_array())
        assert np.array_equal(ops.to_grayscale(gray), gray)

    def test_grayscale_handles_alpha(self) -> None:
        rgba = np.dstack([_array(), np.full((300, 400), 255, dtype=np.uint8)])
        assert ops.to_grayscale(rgba).ndim == 2

    @pytest.mark.parametrize(
        "operation",
        [
            ops.clahe,
            ops.normalise_illumination,
            ops.suppress_glare,
            ops.unsharp_mask,
            ops.denoise,
            ops.otsu_threshold,
            ops.adaptive_threshold,
        ],
    )
    def test_operations_preserve_dimensions(self, operation) -> None:
        """Only ``upscale`` and ``warp`` may change size. Everything else must
        not, or the region coordinates from Step 15 would stop lining up.
        """
        source = _array()
        result = operation(source)
        assert result.shape[:2] == source.shape[:2]

    @pytest.mark.parametrize(
        "operation",
        [
            ops.clahe,
            ops.normalise_illumination,
            ops.suppress_glare,
            ops.unsharp_mask,
            ops.denoise,
            ops.otsu_threshold,
            ops.adaptive_threshold,
        ],
    )
    def test_operations_return_uint8(self, operation) -> None:
        assert operation(_array()).dtype == np.uint8

    def test_thresholding_produces_two_values(self) -> None:
        """A binarised image must be genuinely binary — decoders rely on it."""
        assert set(np.unique(ops.otsu_threshold(_array()))) <= {0, 255}

    def test_upscale_enlarges(self) -> None:
        result = ops.upscale(_array(400, 300), factor=2.0)
        assert result.shape[:2] == (600, 800)

    def test_upscale_below_one_is_a_no_op(self) -> None:
        source = _array()
        assert ops.upscale(source, factor=0.5).shape == source.shape

    def test_flatfield_flattens_a_lighting_gradient(self) -> None:
        """The core illumination fix, measured rather than assumed."""
        height, width = 300, 400
        gradient = np.tile(np.linspace(40, 220, width, dtype=np.uint8), (height, 1))
        corrected = ops.normalise_illumination(gradient)

        before = float(gradient[:, :50].mean() - gradient[:, -50:].mean())
        after = float(corrected[:, :50].mean() - corrected[:, -50:].mean())
        assert abs(after) < abs(before) / 4, "gradient was not meaningfully flattened"

    def test_deglare_leaves_clean_images_alone(self) -> None:
        """No glare present means no processing — avoid gratuitous change."""
        source = ops.to_grayscale(_array())
        assert np.array_equal(ops.suppress_glare(source), source)

    def test_deglare_reduces_saturated_area(self) -> None:
        source = ops.to_grayscale(_array())
        source[100:200, 100:200] = 255  # a blown-out highlight
        before = ops.estimate_glare_fraction(source)
        after = ops.estimate_glare_fraction(ops.suppress_glare(source))
        assert after < before

    def test_clahe_increases_contrast_on_a_flat_image(self) -> None:
        low_contrast = np.full((300, 400), 128, dtype=np.uint8)
        low_contrast[100:200, 100:300] = 138  # barely visible
        assert ops.clahe(low_contrast).std() > low_contrast.std()


class TestRotation:
    @pytest.mark.parametrize("degrees", [0, 90, 180, 270])
    def test_valid_rotations(self, degrees: int) -> None:
        source = _array(400, 300)
        result = ops.rotate(source, degrees)
        expected = (300, 400) if degrees in (0, 180) else (400, 300)
        assert result.shape[:2] == expected

    def test_four_rotations_return_to_the_original(self) -> None:
        source = _array()
        result = source
        for _ in range(4):
            result = ops.rotate(result, 90)
        assert np.array_equal(result, source)

    def test_non_right_angle_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="multiples of 90"):
            ops.rotate(_array(), 45)


class TestEncoding:
    def test_encodes_to_png(self) -> None:
        """★ PNG, never JPEG.

        JPEG's block transform rings at exactly the high-contrast edges that
        define QR modules. Re-encoding a variant as JPEG can turn a decodable
        code into an undecodable one.
        """
        assert ops.encode_png(_array())[:8] == b"\x89PNG\r\n\x1a\n"

    def test_encoding_is_lossless(self) -> None:
        source = ops.to_grayscale(_array())
        restored = cv2.imdecode(
            np.frombuffer(ops.encode_png(source), dtype=np.uint8), cv2.IMREAD_GRAYSCALE
        )
        assert np.array_equal(restored, source), "encoding altered pixel data"


class TestDocumentDetection:
    def test_finds_a_clear_quadrilateral(self) -> None:
        canvas = np.full((600, 800, 3), 30, dtype=np.uint8)
        corners = np.array([[150, 100], [650, 140], [630, 480], [170, 440]], dtype=np.int32)
        cv2.fillPoly(canvas, [corners], (235, 235, 235))
        quad = ops.find_document_quad(canvas)
        assert quad is not None
        assert quad.shape == (4, 2)

    def test_returns_none_when_no_document_is_present(self) -> None:
        """★ Guessing is worse than declining.

        A wrong quadrilateral produces a badly warped image. Warping is one
        variant among many, so skipping it costs little; corrupting the input
        costs a decode.
        """
        assert ops.find_document_quad(_array(800, 600)) is None

    def test_warp_produces_a_rectangle(self) -> None:
        canvas = np.full((600, 800, 3), 30, dtype=np.uint8)
        corners = np.array([[150, 100], [650, 140], [630, 480], [170, 440]], dtype=np.int32)
        cv2.fillPoly(canvas, [corners], (235, 235, 235))
        quad = ops.find_document_quad(canvas)
        assert quad is not None
        warped = ops.warp_to_quad(canvas, quad)
        assert warped.shape[0] > 10 and warped.shape[1] > 10


# --------------------------------------------------------------------------- #
# Strategy table
# --------------------------------------------------------------------------- #


class TestStrategyTable:
    def test_names_are_unique(self) -> None:
        names = [s.name for s in STRATEGIES]
        assert len(names) == len(set(names))

    def test_every_tier_zero_strategy_is_cheap(self) -> None:
        """Tier 0 runs on every single upload. Keep it to two operations."""
        for strategy in STRATEGIES:
            if strategy.tier == 0:
                assert len(strategy.operations) <= 2

    def test_every_strategy_declares_what_it_addresses(self) -> None:
        """The ``addresses`` set is Step 14's entire integration surface."""
        for strategy in STRATEGIES:
            assert strategy.addresses, f"{strategy.name} addresses nothing"

    def test_every_problem_has_at_least_one_strategy(self) -> None:
        covered = set(itertools.chain.from_iterable(s.addresses for s in STRATEGIES))
        assert set(Problem) == covered, f"uncovered problems: {set(Problem) - covered}"

    def test_warp_strategies_are_flagged(self) -> None:
        for strategy in STRATEGIES:
            if strategy.name.startswith("warp"):
                assert strategy.needs_warp is True


class TestStrategySelection:
    def test_no_quality_model_selects_the_full_matrix(self) -> None:
        """Step 4 behaviour: no model available, so run everything."""
        assert len(select_strategies(None)) == len(STRATEGIES)

    def test_original_is_always_first(self) -> None:
        """★ Ordering is declaration order within a tier, not alphabetical.

        An already-good capture must decode on the very first variant. Sorting
        by name would put "gray" first and add work to every successful upload.
        """
        assert select_strategies(None)[0].name == "original"

    def test_tiers_are_ordered(self) -> None:
        tiers = [s.tier for s in select_strategies(None)]
        assert tiers == sorted(tiers)

    def test_max_tier_limits_cost(self) -> None:
        assert all(s.tier <= 1 for s in select_strategies(None, max_tier=1))

    def test_limit_caps_the_count(self) -> None:
        assert len(select_strategies(None, limit=5)) == 5

    def test_quality_reorders_without_narrowing(self) -> None:
        """⛔ EXPECTATION REVERSED BY MEASUREMENT — 17 Aug 2026.

        This used to assert `len(narrowed) < len(STRATEGIES)` — that a quality
        model should SHRINK the matrix. Step 14 measured what that actually did:
        when quality reported "this photo looks fine", 23 strategies became 3,
        discarding `gray+adaptive` — the only strategy that rescued a heavily
        blurred card the original failed on.

        Four real corpus images are sharp, bright and well-sized yet still
        undecodable, and those are exactly the inputs for which quality reports
        no problem. Shrinking would have removed their best remaining chance.

        The payoff is REORDERING: the likeliest strategy runs sooner, and
        nothing is taken away. See D141.
        """
        good = QualityScores(
            blur=0.95,
            glare=0.95,
            skew_degrees=0.5,
            resolution_adequate=True,
            crop_complete=True,
            shadow=0.95,
            decodability=0.9,
        )
        selected = select_strategies(good)

        assert {s.name for s in selected} == {s.name for s in select_strategies(None)}
        assert selected[0].tier == 0, "the cheapest tier must still run first"

    def test_blurry_image_keeps_blur_strategies(self) -> None:
        blurry = QualityScores(
            blur=0.2,
            glare=0.95,
            skew_degrees=0.0,
            resolution_adequate=True,
            crop_complete=True,
            shadow=0.95,
            decodability=0.8,
        )
        selected = select_strategies(blurry)
        assert any(Problem.BLUR in s.addresses for s in selected)

    def test_low_decodability_falls_back_to_everything(self) -> None:
        """★ When the model expects trouble but cannot say what, trust it less,
        not more. Skipping the one strategy that would have worked is the
        expensive mistake.
        """
        uncertain = QualityScores(
            blur=0.8,
            glare=0.8,
            skew_degrees=0.0,
            resolution_adequate=True,
            crop_complete=True,
            shadow=0.8,
            decodability=0.2,
        )
        assert len(select_strategies(uncertain)) == len(STRATEGIES)

    def test_problem_mapping_flags_skew(self) -> None:
        skewed = QualityScores(
            blur=0.9,
            glare=0.9,
            skew_degrees=25.0,
            resolution_adequate=True,
            crop_complete=True,
            shadow=0.9,
            decodability=0.7,
        )
        assert Problem.PERSPECTIVE in problems_from_quality(skewed)


# --------------------------------------------------------------------------- #
# Generation
# --------------------------------------------------------------------------- #


class TestGeneration:
    def test_yields_image_variants(self, generator, photo) -> None:
        variant = next(iter(generator.generate(photo)))
        assert isinstance(variant, ImageVariant)
        assert variant.strategy
        assert variant.data

    def test_generation_is_lazy(self, generator, photo) -> None:
        """★ Contract 1.1.0 exists for this.

        Taking one variant must not compute all twenty-three. The Step 5 cascade
        stops at the first success, so eager generation would waste hundreds of
        megabytes and most of a second on every successful upload.
        """
        stream = generator.generate(photo)
        assert isinstance(stream, itertools.chain) or hasattr(stream, "__next__")
        next(stream)  # if this materialised everything, the type would be a list
        assert not isinstance(stream, list)

    def test_first_variant_is_the_unmodified_image(self, generator, photo) -> None:
        assert next(iter(generator.generate(photo))).strategy == "original"

    def test_variants_are_ordered_by_tier(self, generator, photo) -> None:
        order = {s.name: s.tier for s in STRATEGIES}
        tiers = [order[v.strategy] for v in generator.generate(photo)]
        assert tiers == sorted(tiers)

    def test_all_variants_are_png(self, generator, photo) -> None:
        for variant in generator.generate(photo):
            assert variant.data[:8] == b"\x89PNG\r\n\x1a\n"

    def test_all_variants_are_decodable(self, generator, photo) -> None:
        for variant in generator.generate(photo):
            with Image.open(io.BytesIO(variant.data)) as image:
                assert image.size[0] > 0

    def test_strategy_names_are_unique_per_run(self, generator, photo) -> None:
        keys = [(v.strategy, v.rotation) for v in generator.generate(photo)]
        assert len(keys) == len(set(keys))

    def test_limit_is_respected(self, photo) -> None:
        capped = PreprocessingVariantGenerator(limit=3)
        assert len(list(capped.generate(photo))) == 3

    def test_max_tier_reduces_output(self, photo) -> None:
        cheap = PreprocessingVariantGenerator(max_tier=0)
        assert len(list(cheap.generate(photo))) <= 3

    def test_rotations_are_off_by_default(self, generator, photo) -> None:
        """★ QR finder patterns are rotation-invariant and EXIF orientation is
        already applied in Step 3. Enabling rotations multiplies the work for
        close to no gain.
        """
        assert generator.rotations == ()
        assert all(v.rotation == 0 for v in generator.generate(photo))

    def test_rotations_can_be_enabled(self, photo) -> None:
        rotating = PreprocessingVariantGenerator(max_tier=0, rotations=(90, 180))
        assert {v.rotation for v in rotating.generate(photo)} == {0, 90, 180}

    def test_undecodable_input_raises(self, photo) -> None:
        broken = photo.model_copy(update={"data": b"\x89PNG\r\n\x1a\n" + b"garbage" * 100})
        with pytest.raises(ImagingError):
            next(iter(PreprocessingVariantGenerator().generate(broken)))

    def test_a_failing_strategy_does_not_abort_the_run(self, photo) -> None:
        """One broken recipe must not deny the decoder the other twenty-two."""
        variants = list(PreprocessingVariantGenerator().generate(photo))
        assert len(variants) >= len([s for s in STRATEGIES if not s.needs_warp])


class TestRegionSeam:
    """Step 15 seam — crop to a located QR before processing."""

    def test_region_crops_the_source(self, generator, photo) -> None:
        region = QrRegion(x=100, y=80, width=200, height=200, confidence=0.9)
        cropped = next(iter(generator.generate(photo, region=region)))
        full = next(iter(generator.generate(photo)))
        assert len(cropped.data) < len(full.data)

    def test_region_adds_quiet_zone_padding(self, photo) -> None:
        """★ Cropping exactly to a detected box removes the quiet zone a decoder
        needs. We deliberately over-crop.
        """
        padded = PreprocessingVariantGenerator(region_padding=0.25, max_tier=0)
        region = QrRegion(x=200, y=150, width=200, height=200, confidence=0.9)
        variant = next(iter(padded.generate(photo, region=region)))
        with Image.open(io.BytesIO(variant.data)) as image:
            assert image.size[0] > 200, "no padding was added"

    def test_implausible_region_falls_back_to_the_whole_image(self, generator, photo) -> None:
        tiny = QrRegion(x=0, y=0, width=2, height=2, confidence=0.1)
        assert next(iter(generator.generate(photo, region=tiny))).data

    def test_region_at_the_edge_is_clamped(self, generator, photo) -> None:
        edge = QrRegion(x=700, y=500, width=300, height=300, confidence=0.8)
        assert next(iter(generator.generate(photo, region=edge))).data


class TestQualitySeam:
    """Step 14 seam — REORDER the strategy set using model output."""

    def test_quality_preserves_the_variant_count(self, generator, photo) -> None:
        """⛔ Was `assert len(with_model) < len(without_model)`.

        Reversed for the reason in `test_quality_reorders_without_narrowing`:
        an advisory component that can DELETE a decode attempt can cause a
        failure that would not otherwise have happened (D120). Quality decides
        what is tried EARLIER, never what is skipped.
        """
        good = QualityScores(
            blur=0.95,
            glare=0.95,
            skew_degrees=0.0,
            resolution_adequate=True,
            crop_complete=True,
            shadow=0.95,
            decodability=0.95,
        )
        with_model = list(generator.generate(photo, quality=good))
        without_model = list(generator.generate(photo))

        assert len(with_model) == len(without_model)
        assert {v.strategy for v in with_model} == {v.strategy for v in without_model}

    def test_quality_is_optional(self, generator, photo) -> None:
        """The pipeline must run identically before Step 14 exists."""
        assert list(generator.generate(photo, quality=None))

    def test_both_seams_together(self, generator, photo) -> None:
        region = QrRegion(x=100, y=100, width=300, height=300, confidence=0.9)
        quality = QualityScores(
            blur=0.9,
            glare=0.9,
            skew_degrees=0.0,
            resolution_adequate=True,
            crop_complete=True,
            shadow=0.9,
            decodability=0.9,
        )
        assert list(generator.generate(photo, region=region, quality=quality))


# --------------------------------------------------------------------------- #
# Step 7.5 — QR localisation and QR-relative working size
#
# These lock in the fix for the bug that cost us the real decode rate: at
# working_max_edge=4000 a 4032px phone photo was never downscaled, every
# strategy ran on 12 megapixels at ~2.6s each, and 17 of 23 strategies never
# ran inside the time budget.
# --------------------------------------------------------------------------- #


def _photo_of_card(payload: str, frame=(4032, 3024), card_fraction=0.55) -> bytes:
    """A realistic phone photo: a card occupying part of a large frame."""
    import io

    from PIL import Image

    from tests.fixtures.qr_images import encode_jpeg, render_card

    card = Image.open(io.BytesIO(encode_jpeg(render_card(payload)))).convert("RGB")
    canvas = Image.new("RGB", frame, (95, 92, 88))
    width = int(frame[0] * card_fraction)
    height = int(width * card.height / card.width)
    canvas.paste(
        card.resize((width, height), Image.LANCZOS),
        (frame[0] // 2 - width // 2, frame[1] // 2 - height // 2),
    )
    buffer = io.BytesIO()
    canvas.save(buffer, "JPEG", quality=85)
    return buffer.getvalue()


def test_find_qr_region_locates_a_real_qr(builder):
    """The localiser must agree with the decoder about where the QR is."""
    import cv2
    import numpy as np

    from tests.fixtures.qr_images import encode_jpeg, render_card

    data = encode_jpeg(render_card(builder.build()))
    image = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)

    region = ops.find_qr_region(image)
    assert region is not None, "failed to locate a QR that decodes perfectly"

    zxingcpp = pytest.importorskip("zxingcpp")
    truth = zxingcpp.read_barcodes(cv2.cvtColor(image, cv2.COLOR_BGR2GRAY))[0].position
    assert abs(region[0] - truth.top_left.x) < 25
    assert abs(region[1] - truth.top_left.y) < 25


def test_find_qr_region_returns_none_without_a_qr():
    """⛔ False positives are worse than misses.

    The first version required only three similar nested squares, so ordinary
    card furniture produced a 'QR' covering most of the frame. The right-isoceles
    geometry check is what stops that.
    """
    import cv2
    import numpy as np

    canvas = np.full((3000, 4000), 235, np.uint8)
    for x, y, w, h in [(300, 300, 3400, 2400), (400, 400, 1200, 300), (2600, 1800, 900, 900)]:
        for inset, thickness in ((0, 18), (40, 10), (80, 6)):
            cv2.rectangle(
                canvas, (x + inset, y + inset), (x + w - inset, y + h - inset), 40, thickness
            )

    assert ops.find_qr_region(canvas) is None


def test_large_photo_is_downscaled_relative_to_the_qr(builder):
    """★ The regression test for the Step 4 bug.

    A 12MP photo must come back materially smaller, or every strategy pays 12MP
    of cost and the budget buys only a handful of them.
    """
    from avs.ingest import ImageIngestor

    ingestor = ImageIngestor(scanner=None)
    validated = ingestor.ingest(_photo_of_card(builder.build()))
    generator = PreprocessingVariantGenerator()

    import cv2
    import numpy as np

    source = cv2.imdecode(np.frombuffer(validated.data, np.uint8), cv2.IMREAD_COLOR)
    fitted = generator._fit_working_size(source)

    # The QR is located and the frame is cropped to it with context, so the
    # working image is a small fraction of a 12MP original.
    assert max(fitted.shape[:2]) < max(source.shape[:2]) * 0.5, (
        "a 12MP photo was not reduced; every strategy will pay 12MP of cost"
    )
    assert min(fitted.shape[:2]) > 200, "cropped so hard the QR lost its quiet zone"


def test_downscaling_does_not_break_the_decode(builder):
    """Speed is worthless if it costs us the decode."""
    from avs.ingest import ImageIngestor
    from avs.qr import QrDecoderCascade

    validated = ImageIngestor(scanner=None).ingest(_photo_of_card(builder.build()))
    result = QrDecoderCascade().decode(PreprocessingVariantGenerator().generate(validated))

    assert result.success, "downscaling lost a QR that decodes at full resolution"


def test_all_strategies_fit_in_the_budget_on_a_12mp_photo(builder):
    """The whole point of the fix: the strategy set must actually run.

    Uses a QR-less frame — the expensive case, because zxing searches the entire
    image before giving up, and that is precisely when we need the later
    strategies most.
    """
    import time

    from avs.ingest import ImageIngestor

    blank = _photo_of_card("https://example.com/no-secure-qr-here")
    validated = ImageIngestor(scanner=None).ingest(blank)

    started = time.perf_counter()
    count = sum(1 for _ in PreprocessingVariantGenerator().generate(validated))
    elapsed = time.perf_counter() - started

    assert count >= 18, f"only {count} strategies produced a variant"
    assert elapsed < 9.0, (
        f"generation took {elapsed:.1f}s of the 12s document budget. Before the "
        f"Step 7.5 fix this was ~50s and only 4-6 strategies ever ran."
    )


def test_mislocated_qr_must_not_lose_a_decode(builder, monkeypatch):
    """⛔ Regression guard for the Step 7.5 crop.

    Cropping to a located QR made the pipeline 5x faster but cost one real
    decode: the box landed in the wrong place and the QR was discarded before
    any decoder saw it. Speed is never worth losing a verification.

    Here localisation is forced to return a deliberately wrong region. The
    document must still decode, via the uncropped fallback.
    """
    from avs.ingest import ImageIngestor
    from avs.qr import QrDecoderCascade

    validated = ImageIngestor(scanner=None).ingest(_photo_of_card(builder.build()))

    # A plausible-looking box in completely the wrong corner.
    monkeypatch.setattr(ops, "find_qr_region", lambda *a, **k: (10, 10, 300, 300))

    generator = PreprocessingVariantGenerator()
    result = QrDecoderCascade().decode(generator.generate(validated))

    assert result.success, "a mislocated crop threw away a decodable QR"


def test_uncropped_fallback_is_offered_early(builder, monkeypatch):
    """The safety net is worthless if it arrives after the time budget."""
    from avs.ingest import ImageIngestor

    validated = ImageIngestor(scanner=None).ingest(_photo_of_card(builder.build()))
    monkeypatch.setattr(ops, "find_qr_region", lambda *a, **k: (10, 10, 300, 300))

    variants = []
    for index, variant in enumerate(PreprocessingVariantGenerator().generate(validated)):
        variants.append(variant)
        if index >= 3:
            break

    # The full-frame retry must be among the first couple of variants.
    sizes = {len(v.data) for v in variants[:2]}
    assert len(sizes) == 2, "the uncropped frame was not offered immediately after the crop"


# --------------------------------------------------------------------------- #
# ⛔ find_qr_region — two bugs found by real corpus measurement, 17 Aug 2026
# --------------------------------------------------------------------------- #


def _encoded_qr():
    """A genuinely decodable QR — not a random grid, which would look like one
    to a finder-pattern search while decoding to nothing."""
    import cv2
    import numpy as np

    rng = np.random.default_rng(3)
    payload = "".join(str(int(d)) for d in rng.integers(0, 10, 1200))
    return cv2.QRCodeEncoder_create().encode(payload)


def _card(qr_px: int, *, decoys: bool = False):
    """A card face: printed text lines, optional QR, optional decoy squares."""
    import cv2
    import numpy as np

    rng = np.random.default_rng(3)
    width, height = 2400, 1500
    frame = np.full((height + 400, width + 400, 3), 60, np.uint8)
    face = np.full((height, width, 3), 245, np.uint8)

    for index in range(30):
        y = 90 + index * 40
        cv2.line(face, (60, y), (60 + int(rng.integers(400, width - 500)), y), (25, 25, 25), 7)

    if decoys:
        # Three concentric squares at QR-ish corners — the shape that fooled
        # the old detector into inventing a region spanning the whole card.
        for cx, cy in ((300, 300), (1800, 300), (300, 1100)):
            cv2.rectangle(face, (cx, cy), (cx + 120, cy + 120), (20, 20, 20), -1)
            cv2.rectangle(face, (cx + 20, cy + 20), (cx + 100, cy + 100), (245, 245, 245), -1)

    if qr_px:
        qr = cv2.cvtColor(
            cv2.resize(_encoded_qr(), (qr_px, qr_px), interpolation=cv2.INTER_NEAREST),
            cv2.COLOR_GRAY2BGR,
        )
        face[height - qr_px - 60 : height - 60, width - qr_px - 60 : width - 60] = qr

    frame[200 : 200 + height, 200 : 200 + width] = face
    return frame


def test_located_region_is_always_square():
    """⛔ THE BUG THAT BROKE EVERY px_per_module MEASUREMENT.

    Run against a real corpus, this function returned a 2788x5417 region —
    aspect 0.51 — and called it a QR. Five of six such regions were non-square,
    and none decoded even cropped and upscaled 4x.

    A QR is square. Perspective skews the finder-pattern bounding box, but never
    to 2:1.
    """
    from avs.imaging.ops import find_qr_region, to_grayscale

    for qr_px in (400, 500, 700, 900, 1100):
        box = find_qr_region(to_grayscale(_card(qr_px)))
        assert box is not None, f"lost a real {qr_px}px QR"
        aspect = box[2] / box[3]
        assert 0.72 <= aspect <= 1.39, f"{qr_px}px QR -> aspect {aspect:.2f}"


def test_no_region_is_invented_on_a_card_without_a_qr():
    """⛔ D136: the old detector reported a QR in 16 of 19 images that have none.

    The decoy squares here are the exact shape that fooled it — three
    concentric squares roughly at QR corners.
    """
    from avs.imaging.ops import find_qr_region, to_grayscale

    assert find_qr_region(to_grayscale(_card(0))) is None
    assert find_qr_region(to_grayscale(_card(0, decoys=True))) is None


def test_the_located_region_is_about_the_size_of_the_real_qr():
    """★ The old code kept the LARGEST candidate, so a phantom spanning the card
    always beat the real QR — inflating every corpus measurement roughly 3x.

    Selection is now by finder-pattern size, so the reported box tracks the
    actual code.
    """
    from avs.imaging.ops import find_qr_region, to_grayscale

    for qr_px in (400, 500, 900, 1100):
        box = find_qr_region(to_grayscale(_card(qr_px)))
        assert box is not None
        error = abs(box[2] - qr_px) / qr_px
        assert error < 0.35, f"{qr_px}px QR reported as {box[2]}px ({error:.0%} out)"


def test_finder_geometry_matches_real_qr_proportions():
    """⛔ The leg check used to be `> 1.5 * marker_width` — about 9x too loose,
    which is why ordinary card furniture qualified.

    For an N-module code the leg between adjacent finder centres is (N - 7)
    modules and a marker is 7, so the ratio is (N - 7) / 7. Aadhaar's Secure QR
    is version 21-22, giving 12.9-13.4.
    """
    from avs.imaging.ops import MAX_LEG_TO_MARKER, MIN_LEG_TO_MARKER

    for modules in (97, 101):  # the Aadhaar range
        ratio = (modules - 7) / 7
        assert MIN_LEG_TO_MARKER <= ratio <= MAX_LEG_TO_MARKER

    assert MIN_LEG_TO_MARKER > 1.5, "the old, far-too-loose bound must not return"


# --------------------------------------------------------------------------- #
# ⛔ Step 14 — quality REORDERS the variant matrix, it never shrinks it
# --------------------------------------------------------------------------- #


def _scores(**overrides):
    from avs.contracts import QualityScores

    base = {
        "blur": 1.0,
        "glare": 1.0,
        "skew_degrees": 1.0,
        "resolution_adequate": True,
        "crop_complete": True,
        "shadow": 1.0,
        "decodability": 0.75,
        "model_version": "test",
    }
    base.update(overrides)
    return QualityScores(**base)


def test_quality_never_removes_a_strategy():
    """⛔⛔ THE D120 VIOLATION THIS PREVENTS.

    `select_strategies` used to FILTER on the detected problems. Measured: when
    quality reported "this photo looks fine", 23 strategies were cut to 3 — and
    among the 20 discarded was `gray+adaptive`, the only strategy that rescued a
    heavily blurred test card (original failed, adaptive succeeded at attempt 6).

    Four real corpus images are sharp, bright and well-sized yet undecodable —
    exactly the inputs for which quality reports no problem. Filtering would
    have stripped their best remaining chance on precisely the images needing it
    most.

    An advisory component that can DELETE a decode attempt can cause a failure
    that would not otherwise happen.
    """
    from avs.imaging.strategy import select_strategies

    everything = {s.name for s in select_strategies(None)}

    for scores in (
        _scores(),  # "looks perfect" — the dangerous case
        _scores(blur=0.05, decodability=0.05),
        _scores(glare=0.05, decodability=0.05),
        _scores(resolution_adequate=False, decodability=0.1),
        _scores(skew_degrees=30.0),
        _scores(decodability=0.0),
    ):
        selected = {s.name for s in select_strategies(scores)}
        assert selected == everything, f"quality removed {everything - selected}"


def test_quality_actually_changes_the_order():
    """★ Reordering that reorders nothing is decoration.

    An earlier version marked EVERY problem as detected whenever decodability
    was low, which made every strategy equally relevant and produced an ordering
    byte-identical to having no quality model. This asserts the signal survives.
    """
    from avs.imaging.strategy import select_strategies

    base = [s.name for s in select_strategies(None)]
    blurry = [s.name for s in select_strategies(_scores(blur=0.1, decodability=0.2))]
    glary = [s.name for s in select_strategies(_scores(glare=0.1, decodability=0.2))]

    assert blurry != base, "blur produced the deterministic order unchanged"
    assert glary != base, "glare produced the deterministic order unchanged"
    assert blurry != glary, "different problems must produce different orders"


def test_the_original_is_always_tried_first():
    """⛔ Every one of the 8 real corpus successes decoded on `original`.

    No quality signal may push it back — that would add work to every
    successful upload.
    """
    from avs.imaging.strategy import select_strategies

    for scores in (None, _scores(), _scores(blur=0.01, glare=0.01, decodability=0.01)):
        assert select_strategies(scores)[0].name == "original"


def test_cheap_tiers_still_come_before_expensive_ones():
    """⚠ Tier stays the primary sort key. A heuristic finding an expensive
    strategy 'apt' must not delay a cheap one that might simply work."""
    from avs.imaging.strategy import select_strategies

    tiers = [s.tier for s in select_strategies(_scores(blur=0.1, decodability=0.1))]
    assert tiers == sorted(tiers)
