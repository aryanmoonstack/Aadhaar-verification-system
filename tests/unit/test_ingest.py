"""Ingest and validation tests — Step 3. The first security boundary.

Image decoders are among the most exploited code in any stack. This suite
verifies that hostile input is rejected by the *earliest* possible check and
never reaches a decoder, and that the two privacy guarantees hold: EXIF is
stripped, and the file extension is never trusted.
"""

from __future__ import annotations

import io

import pytest
from PIL import Image

from avs.contracts import CaptureMethod, ErrorCode, ValidatedImage
from avs.ingest import (
    HEIF_AVAILABLE,
    ClamAvScanner,
    FileKind,
    ImageIngestor,
    IngestError,
    NullScanner,
    ScanResult,
    detect,
)
from tests.fixtures.images import (
    FAKE_HEADERS,
    corrupt_bytes,
    make_bomb_png,
    make_exif_jpeg,
    make_image_bytes,
)


@pytest.fixture
def ingestor() -> ImageIngestor:
    """Default limits, no scanner."""
    return ImageIngestor()


@pytest.fixture
def lenient() -> ImageIngestor:
    """Relaxed size floor, for fixtures that are deliberately small."""
    return ImageIngestor(min_bytes=1_000, min_width=100, min_height=100)


# --------------------------------------------------------------------------- #
# Magic-byte detection
# --------------------------------------------------------------------------- #


class TestMagicDetection:
    @pytest.mark.parametrize(
        ("fmt", "expected"),
        [("JPEG", FileKind.JPEG), ("PNG", FileKind.PNG), ("WEBP", FileKind.WEBP)],
    )
    def test_accepted_formats_are_identified(self, fmt: str, expected: FileKind) -> None:
        assert detect(make_image_bytes(fmt=fmt)).kind is expected

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("pdf", FileKind.PDF),
            ("zip", FileKind.ZIP),
            ("gzip", FileKind.ZIP),
            ("elf", FileKind.EXECUTABLE),
            ("pe", FileKind.EXECUTABLE),
            ("javaclass", FileKind.EXECUTABLE),
            ("gif", FileKind.GIF),
            ("bmp", FileKind.BMP),
            ("tiff", FileKind.TIFF),
            ("svg", FileKind.SCRIPT),
            ("html", FileKind.SCRIPT),
        ],
    )
    def test_disallowed_types_are_identified_precisely(self, name: str, expected: FileKind) -> None:
        """Naming the type precisely is what makes the error message useful."""
        detected = detect(FAKE_HEADERS[name])
        assert detected.kind is expected
        assert detected.is_accepted is False

    def test_unknown_bytes_return_unknown_not_an_exception(self) -> None:
        assert detect(FAKE_HEADERS["random"]).kind is FileKind.UNKNOWN

    def test_short_input_is_safe(self) -> None:
        assert detect(b"").kind is FileKind.UNKNOWN
        assert detect(b"\xff\xd8").kind is FileKind.UNKNOWN

    def test_every_rejection_has_a_user_message(self) -> None:
        for kind in FileKind:
            if not kind.is_accepted:
                assert kind.rejection_reason.strip()


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #


class TestAcceptedUploads:
    def test_jpeg_is_accepted(self, ingestor: ImageIngestor) -> None:
        image = ingestor.ingest(make_image_bytes(fmt="JPEG"))
        assert isinstance(image, ValidatedImage)
        assert image.mime_type == "image/jpeg"
        assert (image.width, image.height) == (800, 600)

    def test_png_is_accepted(self, ingestor: ImageIngestor) -> None:
        assert ingestor.ingest(make_image_bytes(fmt="PNG")).mime_type == "image/png"

    def test_webp_is_accepted(self, ingestor: ImageIngestor) -> None:
        assert ingestor.ingest(make_image_bytes(fmt="WEBP")).mime_type == "image/webp"

    def test_hash_is_of_the_original_bytes(self, ingestor: ImageIngestor) -> None:
        """The audit identity must be what the employee uploaded, not our
        re-encoding — which would drift with Pillow versions.
        """
        import hashlib

        data = make_image_bytes()
        assert ingestor.ingest(data).sha256 == hashlib.sha256(data).hexdigest()

    def test_size_bytes_reports_the_original_upload(self, ingestor: ImageIngestor) -> None:
        data = make_image_bytes()
        assert ingestor.ingest(data).size_bytes == len(data)

    def test_capture_method_is_carried_through(self, ingestor: ImageIngestor) -> None:
        image = ingestor.ingest(make_image_bytes(), capture_method=CaptureMethod.CAMERA)
        assert image.capture_method is CaptureMethod.CAMERA

    def test_output_is_decodable(self, ingestor: ImageIngestor) -> None:
        image = ingestor.ingest(make_image_bytes())
        with Image.open(io.BytesIO(image.data)) as reopened:
            assert reopened.size == (800, 600)

    def test_repr_never_leaks_image_bytes(self, ingestor: ImageIngestor) -> None:
        text = repr(ingestor.ingest(make_image_bytes()))
        assert "data=" not in text
        assert "sha256=" in text


# --------------------------------------------------------------------------- #
# Rejections
# --------------------------------------------------------------------------- #


class TestRejectedUploads:
    @pytest.mark.parametrize(
        "name",
        ["pdf", "zip", "gzip", "elf", "pe", "javaclass", "gif", "bmp", "tiff", "svg", "html"],
    )
    def test_disallowed_types_are_rejected(self, lenient: ImageIngestor, name: str) -> None:
        with pytest.raises(IngestError) as exc:
            lenient.ingest(FAKE_HEADERS[name])
        assert exc.value.code is ErrorCode.UNSUPPORTED_MIME_TYPE

    def test_pdf_rejection_message_is_actionable(self, lenient: ImageIngestor) -> None:
        """Your decision was images-only. The employee must be told what to do
        instead, not just that it failed.
        """
        with pytest.raises(IngestError) as exc:
            lenient.ingest(FAKE_HEADERS["pdf"])
        assert "PDF" in exc.value.user_message
        assert "photo" in exc.value.user_message.lower()

    def test_empty_file(self, lenient: ImageIngestor) -> None:
        with pytest.raises(IngestError) as exc:
            lenient.ingest(b"")
        assert exc.value.code is ErrorCode.CORRUPT_IMAGE

    def test_file_too_small(self, ingestor: ImageIngestor) -> None:
        with pytest.raises(IngestError) as exc:
            ingestor.ingest(make_image_bytes(width=200, height=150, quality=40))
        assert exc.value.code is ErrorCode.FILE_TOO_SMALL

    def test_file_too_large(self) -> None:
        small_cap = ImageIngestor(min_bytes=100, max_bytes=10_000)
        with pytest.raises(IngestError) as exc:
            small_cap.ingest(make_image_bytes())
        assert exc.value.code is ErrorCode.FILE_TOO_LARGE

    def test_dimensions_below_minimum(self) -> None:
        strict = ImageIngestor(min_bytes=1_000, min_width=1920, min_height=1080)
        with pytest.raises(IngestError) as exc:
            strict.ingest(make_image_bytes(width=800, height=600))
        assert exc.value.code is ErrorCode.DIMENSIONS_INVALID
        assert "too small" in exc.value.user_message.lower()

    def test_dimensions_above_maximum(self) -> None:
        tiny_cap = ImageIngestor(min_bytes=1_000, min_width=10, min_height=10, max_dimension=400)
        with pytest.raises(IngestError) as exc:
            tiny_cap.ingest(make_image_bytes(width=800, height=600))
        assert exc.value.code is ErrorCode.DIMENSIONS_INVALID

    def test_corrupt_image_body(self, lenient: ImageIngestor) -> None:
        """Valid header, destroyed body — a truncated or damaged upload."""
        with pytest.raises(IngestError) as exc:
            lenient.ingest(corrupt_bytes(make_image_bytes(), start=100, length=4000))
        assert exc.value.code in {ErrorCode.CORRUPT_IMAGE, ErrorCode.DIMENSIONS_INVALID}

    def test_technical_and_user_messages_differ(self, lenient: ImageIngestor) -> None:
        """Operators need detail; employees need instructions. Never mix them."""
        with pytest.raises(IngestError) as exc:
            lenient.ingest(FAKE_HEADERS["pe"])
        assert exc.value.message != exc.value.user_message
        assert "MZ" not in exc.value.user_message
        assert "binary" not in exc.value.user_message.lower()


# --------------------------------------------------------------------------- #
# ★ The extension is never trusted
# --------------------------------------------------------------------------- #


class TestExtensionIsNeverTrusted:
    """An extension is a claim by the uploader. Magic bytes are evidence."""

    @pytest.mark.parametrize("filename", ["card.jpg", "aadhaar.png", "photo.webp", "x.heic"])
    def test_executable_renamed_as_an_image_is_still_rejected(
        self, lenient: ImageIngestor, filename: str
    ) -> None:
        with pytest.raises(IngestError) as exc:
            lenient.ingest(FAKE_HEADERS["pe"], filename=filename)
        assert exc.value.code is ErrorCode.UNSUPPORTED_MIME_TYPE

    def test_pdf_renamed_as_jpeg_is_still_rejected(self, lenient: ImageIngestor) -> None:
        with pytest.raises(IngestError):
            lenient.ingest(FAKE_HEADERS["pdf"], filename="aadhaar_card.jpg")

    def test_valid_image_with_a_wrong_extension_is_still_accepted(
        self, ingestor: ImageIngestor
    ) -> None:
        """The reverse also holds — content decides, not the name."""
        image = ingestor.ingest(make_image_bytes(fmt="PNG"), filename="scan.pdf")
        assert image.mime_type == "image/png"

    def test_no_filename_at_all_is_fine(self, ingestor: ImageIngestor) -> None:
        assert ingestor.ingest(make_image_bytes()).mime_type == "image/jpeg"

    def test_small_non_image_reports_the_real_problem(self) -> None:
        """★ Check ordering matters for message quality.

        A 4 KB executable renamed to .jpg is below the size floor AND not an
        image. If the size check ran first it would be reported as "image too
        small", which sends the employee off to retake a photo that will never
        work. Type detection runs first so the real problem is named.
        """
        default_floor = ImageIngestor()  # 50 KB minimum
        with pytest.raises(IngestError) as exc:
            default_floor.ingest(FAKE_HEADERS["pe"], filename="aadhaar.jpg")
        assert exc.value.code is ErrorCode.UNSUPPORTED_MIME_TYPE
        assert exc.value.code is not ErrorCode.FILE_TOO_SMALL

    def test_oversized_upload_is_refused_before_type_detection(self) -> None:
        """The upper bound stays first — holding a huge upload in memory to
        sniff its type would be the wrong trade.
        """
        capped = ImageIngestor(max_bytes=1_000)
        with pytest.raises(IngestError) as exc:
            capped.ingest(FAKE_HEADERS["pe"] * 10)
        assert exc.value.code is ErrorCode.FILE_TOO_LARGE


# --------------------------------------------------------------------------- #
# Decompression bombs
# --------------------------------------------------------------------------- #


class TestDecompressionBombs:
    def test_flat_colour_bomb_is_rejected(self) -> None:
        """6000x6000 of solid white: ~120 KB on disk, ~108 MB decoded."""
        bomb = make_bomb_png()
        guard = ImageIngestor(min_bytes=1_000, min_width=10, min_height=10)
        with pytest.raises(IngestError) as exc:
            guard.ingest(bomb)
        assert exc.value.code is ErrorCode.DECOMPRESSION_BOMB

    def test_bomb_is_caught_before_full_decode(self) -> None:
        """The guard runs on header dimensions, so a bomb never allocates.

        If this ever regresses, the failure mode is memory exhaustion in
        production rather than a clean rejection.
        """
        guard = ImageIngestor(min_bytes=1_000, min_width=10, min_height=10, max_pixels=1_000_000)
        with pytest.raises(IngestError) as exc:
            guard.ingest(make_bomb_png(width=3000, height=3000))
        assert exc.value.code is ErrorCode.DECOMPRESSION_BOMB
        assert "pixels" in exc.value.message

    def test_real_photographs_are_not_flagged(self, ingestor: ImageIngestor) -> None:
        """Guard against a false positive that would reject genuine uploads."""
        for fmt in ("JPEG", "PNG", "WEBP"):
            assert ingestor.ingest(make_image_bytes(fmt=fmt, width=1600, height=1200))

    def test_pixel_density_ratio_has_headroom(self, ingestor: ImageIngestor) -> None:
        """A heavily compressed but legitimate photo must still pass."""
        assert ingestor.ingest(make_image_bytes(width=1600, height=1200, quality=30))


# --------------------------------------------------------------------------- #
# ★ Privacy — EXIF stripping
# --------------------------------------------------------------------------- #


class TestExifHandling:
    def test_all_metadata_is_stripped(self, ingestor: ImageIngestor) -> None:
        """A phone photo of an Aadhaar taken at home embeds the employee's home
        GPS coordinates. We never asked for that and must not keep it.
        """
        image = ingestor.ingest(make_exif_jpeg(with_gps=True))
        with Image.open(io.BytesIO(image.data)) as reopened:
            exif = reopened.getexif()
            assert len(exif) == 0, "EXIF survived normalisation"
            assert 0x8825 not in exif, "GPS coordinates survived normalisation"

    def test_camera_make_and_model_are_stripped(self, ingestor: ImageIngestor) -> None:
        image = ingestor.ingest(make_exif_jpeg())
        with Image.open(io.BytesIO(image.data)) as reopened:
            exif = reopened.getexif()
            assert 0x010F not in exif  # Make
            assert 0x0110 not in exif  # Model

    def test_orientation_is_applied_before_stripping(self, ingestor: ImageIngestor) -> None:
        """Orientation 6 means 'rotate 90°'. The pixels must be rotated before
        the tag is discarded, or every such photo arrives sideways — and a
        sideways QR is much harder to decode.
        """
        image = ingestor.ingest(make_exif_jpeg(width=800, height=600, orientation=6))
        assert (image.width, image.height) == (600, 800), "EXIF rotation was not applied"

    def test_upright_images_are_unchanged(self, ingestor: ImageIngestor) -> None:
        image = ingestor.ingest(make_exif_jpeg(width=800, height=600, orientation=1))
        assert (image.width, image.height) == (800, 600)

    def test_stripping_can_be_disabled_deliberately(self) -> None:
        keeper = ImageIngestor(strip_metadata=False)
        image = keeper.ingest(make_exif_jpeg())
        with Image.open(io.BytesIO(image.data)) as reopened:
            assert len(reopened.getexif()) > 0


# --------------------------------------------------------------------------- #
# Malware scanning
# --------------------------------------------------------------------------- #


class _BlockingScanner:
    def scan(self, data: bytes) -> ScanResult:
        return ScanResult(clean=False, signature="Test.Signature", scanner="fake")


class _RecordingScanner:
    def __init__(self) -> None:
        self.received: bytes | None = None

    def scan(self, data: bytes) -> ScanResult:
        self.received = data
        return ScanResult(clean=True, scanner="fake")


class TestMalwareScanning:
    def test_no_scanner_means_no_scanning(self, ingestor: ImageIngestor) -> None:
        assert ingestor.scanner is None
        assert ingestor.ingest(make_image_bytes())

    def test_null_scanner_passes_everything(self) -> None:
        passthrough = ImageIngestor(scanner=NullScanner())
        assert passthrough.ingest(make_image_bytes())

    def test_flagged_file_is_rejected(self) -> None:
        blocking = ImageIngestor(scanner=_BlockingScanner())
        with pytest.raises(IngestError) as exc:
            blocking.ingest(make_image_bytes())
        assert exc.value.code is ErrorCode.MALWARE_DETECTED

    def test_scanner_receives_the_original_bytes(self) -> None:
        """Scanning must happen before any decode or re-encode."""
        recorder = _RecordingScanner()
        data = make_image_bytes()
        ImageIngestor(scanner=recorder).ingest(data)
        assert recorder.received == data

    def test_clamav_fails_closed_when_unreachable(self) -> None:
        """★ A scanner that silently stops scanning is worse than none — operators
        would believe they are protected.
        """
        unreachable = ClamAvScanner(host="127.0.0.1", port=1, timeout=0.1)
        assert unreachable.scan(b"anything").clean is False

    def test_clamav_fail_open_is_opt_in(self) -> None:
        permissive = ClamAvScanner(host="127.0.0.1", port=1, timeout=0.1, fail_open=True)
        assert permissive.scan(b"anything").clean is True


# --------------------------------------------------------------------------- #
# HEIF
# --------------------------------------------------------------------------- #


class TestHeif:
    def test_heif_brand_is_detected(self) -> None:
        header = b"\x00\x00\x00\x18ftypheic" + b"\x00" * 4000
        assert detect(header).kind is FileKind.HEIF

    def test_unknown_iso_bmff_brand_is_not_accepted(self) -> None:
        """MP4 video shares the container format. It is not a still image."""
        header = b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 4000
        assert detect(header).is_accepted is False

    @pytest.mark.skipif(not HEIF_AVAILABLE, reason="pillow-heif not installed")
    def test_heic_is_normalised_to_jpeg(self, lenient: ImageIngestor) -> None:
        """One codec downstream is simpler than three."""
        import os

        import pillow_heif

        source = Image.frombytes("RGB", (800, 600), os.urandom(800 * 600 * 3))
        heif = pillow_heif.from_pillow(source)
        buffer = io.BytesIO()
        heif.save(buffer, format="HEIF", quality=90)
        source.close()

        image = lenient.ingest(buffer.getvalue(), filename="IMG_0001.HEIC")
        assert image.mime_type == "image/jpeg"
        assert (image.width, image.height) == (800, 600)
