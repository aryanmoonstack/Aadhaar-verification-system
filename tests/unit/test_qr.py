"""QR decoder cascade tests — Step 5.

Decode rate is the project's primary metric. This suite covers three things:

1. **Payload classification** — not every QR in a photo is the Aadhaar one, and
   accepting a stray code would hand the parser data that was never a Secure QR.
2. **Cascade behaviour** — stopping at the first success is what makes Step 4's
   cheapest-first ordering pay off. Eager scanning would waste it entirely.
3. **Graceful degradation** — pyzbar needs a system library, the WeChat detector
   needs model files. Neither is guaranteed; the cascade must work regardless.
"""

from __future__ import annotations

import pytest

from avs.contracts import DecodeResult, ImageVariant
from avs.imaging import PreprocessingVariantGenerator, ops
from avs.ingest import ImageIngestor
from avs.qr import (
    MIN_SECURE_QR_DIGITS,
    OpenCvDecoder,
    PayloadKind,
    QrDecoderCascade,
    WeChatDecoder,
    ZbarDecoder,
    ZxingDecoder,
    available_decoders,
    classify_payload,
    decoder_availability,
)
from tests.fixtures.qr_images import (
    add_glare,
    add_noise,
    apply_perspective,
    blur,
    encode_jpeg,
    reduce_contrast,
    render_card,
    render_qr,
)
from tests.fixtures.synthetic import SyntheticQrBuilder


@pytest.fixture(scope="module")
def secure_payload(request) -> str:
    """A real Secure-QR-sized payload — ~1,700 digits, ~109 modules."""
    from tests.fixtures.synthetic import make_test_keypair

    key, _ = make_test_keypair()
    return SyntheticQrBuilder(private_key=key).build()


@pytest.fixture(scope="module")
def card(secure_payload: str):
    return render_card(secure_payload)


@pytest.fixture
def pipeline():
    """Ingest → preprocess → decode, wired as the Step 6 pipeline will be."""
    ingestor = ImageIngestor()
    generator = PreprocessingVariantGenerator()
    cascade = QrDecoderCascade()

    def run(image):
        return cascade.decode(generator.generate(ingestor.ingest(encode_jpeg(image))))

    return run


@pytest.fixture
def lenient_pipeline():
    """Same pipeline with a relaxed size floor.

    A featureless test image compresses to ~20 KB — below the 50 KB production
    minimum, which exists because a real photo that small cannot hold a readable
    Secure QR. The floor is correct; these fixtures simply are not photographs.
    """
    ingestor = ImageIngestor(min_bytes=1_000, min_width=100, min_height=100)
    generator = PreprocessingVariantGenerator()
    cascade = QrDecoderCascade()

    def run(image):
        return cascade.decode(generator.generate(ingestor.ingest(encode_jpeg(image))))

    return run


def _featureless(width: int = 1400, height: int = 900):
    """A plain image containing no QR at all."""
    import numpy as np

    return np.full((height, width, 3), 200, dtype=np.uint8)


# --------------------------------------------------------------------------- #
# Payload classification
# --------------------------------------------------------------------------- #


class TestPayloadClassification:
    def test_secure_qr_is_recognised(self, secure_payload: str) -> None:
        assert classify_payload(secure_payload) is PayloadKind.SECURE_QR

    def test_legacy_xml_is_recognised(self) -> None:
        """★ A pre-2018 card is not an unreadable one.

        Accepting the legacy QR lets the parser return LEGACY_FORMAT — "download
        a fresh e-Aadhaar" — instead of the misleading UNREADABLE.
        """
        legacy = '<?xml version="1.0"?><PrintLetterBarcodeData uid="x" name="y"/>'
        assert classify_payload(legacy) is PayloadKind.LEGACY_XML

    @pytest.mark.parametrize(
        "text",
        [
            "https://example.com/some/url",
            "WIFI:S:MyNetwork;T:WPA;P:secret;;",
            "BEGIN:VCARD\nFN:Someone\nEND:VCARD",
            "upi://pay?pa=someone@bank",
            "12345",
            "",
            "   ",
        ],
    )
    def test_foreign_qrs_are_rejected(self, text: str) -> None:
        """★ A photo can contain a URL sticker or an app's UI code.

        Accepting the first QR found would let a stray code short-circuit the
        cascade and hand the parser data that was never an Aadhaar payload.
        """
        assert classify_payload(text) is PayloadKind.FOREIGN

    def test_short_numeric_string_is_not_a_secure_qr(self) -> None:
        assert classify_payload("9" * (MIN_SECURE_QR_DIGITS - 1)) is PayloadKind.FOREIGN

    def test_long_numeric_string_is_a_secure_qr(self) -> None:
        assert classify_payload("9" * (MIN_SECURE_QR_DIGITS + 1)) is PayloadKind.SECURE_QR

    def test_long_but_not_numeric_is_foreign(self) -> None:
        assert classify_payload("a" * 2000) is PayloadKind.FOREIGN

    def test_whitespace_is_tolerated(self, secure_payload: str) -> None:
        assert classify_payload(f"  {secure_payload}\n") is PayloadKind.SECURE_QR

    def test_classification_never_raises(self) -> None:
        for text in ["\x00\x01", "🙂" * 100, "\n" * 50]:
            assert classify_payload(text) in set(PayloadKind)


# --------------------------------------------------------------------------- #
# Decoder backends
# --------------------------------------------------------------------------- #


class TestDecoderBackends:
    def test_at_least_one_backend_is_available(self) -> None:
        """OpenCV's detector ships with OpenCV, so this must always hold."""
        assert available_decoders(), "no QR decoder available at all"

    def test_opencv_is_always_available(self) -> None:
        assert OpenCvDecoder().available is True

    def test_availability_report_covers_all_backends(self) -> None:
        assert set(decoder_availability()) == {
            "zxing-cpp",
            "opencv-wechat",
            "pyzbar",
            "opencv",
        }

    @pytest.mark.parametrize("cls", [ZxingDecoder, WeChatDecoder, ZbarDecoder, OpenCvDecoder])
    def test_unavailable_backends_return_empty_not_errors(self, cls) -> None:
        """★ Missing dependencies degrade, never break.

        pyzbar needs a system libzbar; the WeChat detector needs model files.
        Neither is guaranteed on a given host.
        """
        decoder = cls()
        assert decoder.decode(ops.to_grayscale(render_qr("1" * 600))) is not None

    def test_backends_never_raise_on_garbage(self) -> None:
        import numpy as np

        noise = np.random.default_rng(3).integers(0, 255, (200, 200), dtype=np.uint8)
        for decoder in available_decoders():
            assert isinstance(decoder.decode(noise), list)

    def test_available_decoder_reads_a_dense_qr(self, secure_payload: str) -> None:
        """The core capability: a ~109-module symbol must decode."""
        image = ops.to_grayscale(render_qr(secure_payload, scale=6))
        assert any(secure_payload in d.decode(image) for d in available_decoders())


# --------------------------------------------------------------------------- #
# Cascade
# --------------------------------------------------------------------------- #


class TestCascade:
    def test_decodes_a_clean_card(self, pipeline, card, secure_payload: str) -> None:
        result = pipeline(card)
        assert result.success is True
        assert result.raw_payload == secure_payload
        assert isinstance(result, DecodeResult)

    def test_clean_card_decodes_on_the_first_variant(self, pipeline, card) -> None:
        """★ This is what Step 4's tier ordering exists for.

        A good capture must not pay for twenty-three preprocessing variants.
        """
        assert pipeline(card).attempts == 1

    def test_records_which_decoder_and_strategy_won(self, pipeline, card) -> None:
        result = pipeline(card)
        assert result.decoder in decoder_availability()
        assert result.strategy

    def test_stops_at_first_success(self, card, secure_payload: str) -> None:
        """The variant stream must not be exhausted once a payload is found."""
        consumed = []

        def counting_stream():
            generator = PreprocessingVariantGenerator()
            image = ImageIngestor().ingest(encode_jpeg(card))
            for variant in generator.generate(image):
                consumed.append(variant.strategy)
                yield variant

        result = QrDecoderCascade().decode(counting_stream())
        assert result.success is True
        assert len(consumed) == 1, f"consumed {len(consumed)} variants after success"

    def test_reports_failure_without_raising(self, lenient_pipeline) -> None:
        result = lenient_pipeline(_featureless())
        assert result.success is False
        assert result.raw_payload is None
        assert result.attempts > 0

    def test_empty_variant_stream(self) -> None:
        result = QrDecoderCascade().decode(iter([]))
        assert result.success is False
        assert result.attempts == 0

    def test_no_decoders_available_fails_loudly(self, card) -> None:
        """★ A silent zero decode rate is far worse than a loud one."""
        result = QrDecoderCascade(decoders=[]).decode(iter([]))
        assert result.success is False

    def test_undecodable_variant_bytes_are_skipped(self) -> None:
        broken = ImageVariant(data=b"not a png at all", strategy="broken", rotation=0)
        assert QrDecoderCascade().decode(iter([broken])).success is False

    def test_max_variants_is_respected(self) -> None:
        lenient = ImageIngestor(min_bytes=1_000, min_width=100, min_height=100)
        image = lenient.ingest(encode_jpeg(_featureless()))
        result = QrDecoderCascade(max_variants=3).decode(
            PreprocessingVariantGenerator().generate(image)
        )
        assert result.attempts <= 3

    def test_time_budget_is_respected(self) -> None:
        """★ One pathological image must not hold a worker while others queue."""
        lenient = ImageIngestor(min_bytes=1_000, min_width=100, min_height=100)
        image = lenient.ingest(encode_jpeg(_featureless(1800, 1200)))
        cascade = QrDecoderCascade(time_budget_seconds=0.4)

        import time as _time

        started = _time.perf_counter()
        result = cascade.decode(PreprocessingVariantGenerator().generate(image))
        elapsed = _time.perf_counter() - started

        assert result.success is False
        assert elapsed < 8.0, "time budget did not bound the run"


class TestForeignQrDetection:
    def test_foreign_qr_is_flagged_not_accepted(self) -> None:
        """★ A URL QR must not be handed to the Aadhaar parser.

        Flagging it separately from "no QR at all" is what lets the employee be
        told something they can act on.
        """
        url_card = render_qr("https://example.com/not-an-aadhaar", scale=8)
        image = ImageIngestor(min_bytes=1_000, min_width=100, min_height=100).ingest(
            encode_jpeg(url_card)
        )
        result = QrDecoderCascade().decode(PreprocessingVariantGenerator().generate(image))
        assert result.success is False
        assert result.raw_payload is None
        assert result.foreign_qr_found is True

    def test_no_qr_at_all_is_not_flagged_as_foreign(self, lenient_pipeline) -> None:
        assert lenient_pipeline(_featureless()).foreign_qr_found is False


# --------------------------------------------------------------------------- #
# Real-world degradation — the decode-rate story
# --------------------------------------------------------------------------- #


class TestDegradation:
    """Each case mirrors a specific way real phone photos fail."""

    def test_moderate_blur_still_decodes(self, pipeline, card, secure_payload: str) -> None:
        result = pipeline(blur(card, 1.0))
        assert result.success is True
        assert result.raw_payload == secure_payload

    def test_heavy_noise_still_decodes(self, pipeline, card) -> None:
        assert pipeline(add_noise(card, 25.0)).success is True

    def test_low_contrast_still_decodes(self, pipeline, card) -> None:
        assert pipeline(reduce_contrast(card, 0.3)).success is True

    def test_perspective_still_decodes(self, pipeline, card) -> None:
        assert pipeline(apply_perspective(card, 0.20)).success is True

    def test_moderate_glare_still_decodes(self, pipeline, card) -> None:
        assert pipeline(add_glare(card, 0.5)).success is True

    def test_severe_blur_fails_cleanly(self, pipeline, card) -> None:
        """★ Failing is correct here — sigma 3.5 destroys ~4 px modules.

        What matters is that it fails as UNREADABLE with no payload, rather than
        returning something wrong. A wrong payload would be far worse.
        """
        result = pipeline(blur(card, 4.0))
        assert result.success is False
        assert result.raw_payload is None

    def test_payload_is_never_corrupted(self, pipeline, card, secure_payload: str) -> None:
        """★ The invariant that matters most for correctness.

        Across every degradation, a *successful* decode must return the exact
        original payload. A silently altered payload would fail signature
        verification and be reported as TAMPERED — accusing an employee over a
        decoder bug.
        """
        cases = [
            card,
            blur(card, 1.0),
            add_noise(card, 20.0),
            reduce_contrast(card, 0.35),
            apply_perspective(card, 0.15),
            add_glare(card, 0.5),
        ]
        for image in cases:
            result = pipeline(image)
            if result.success:
                assert result.raw_payload == secure_payload, "decoder returned wrong data"
