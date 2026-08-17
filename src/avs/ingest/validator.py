"""Image intake and validation — Step 3. The first security boundary.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 3
Provides : ImageIngestor (implements avs.contracts.Ingestor)
Consumes : avs.contracts, avs.ingest.magic, avs.ingest.scanner, Pillow
Used by  : avs.imaging (Step 4)

WHY THIS MODULE IS SECURITY-CRITICAL
------------------------------------
Everything downstream assumes the bytes are safe. Image decoders are among the
most historically exploited code in any stack — libjpeg, libpng, libwebp and
ImageMagick have all shipped remote-code-execution bugs reachable by simply
opening a malicious file.

So the order of operations matters more than any individual check:

    1. upper size    — cheap; refuse an oversized upload immediately
    2. magic bytes   — pure stdlib, no decoder involved
    3. allow-list    — reject anything not JPEG/PNG/WebP/HEIF
    4. lower size    — only meaningful once we know it IS an image
    5. malware scan  — on the ORIGINAL bytes, before any decode
    6. header read   — Pillow lazy open: dimensions WITHOUT decoding pixels
    7. bomb guards   — dimension and pixel-density limits, still no full decode
    8. decode        — only now, and only for input that survived all of the above

Each step is cheaper and safer than the one after it. A malicious file should be
rejected by the earliest possible check, never by the decoder.

PRIVACY: EXIF IS STRIPPED
-------------------------
Phone photos carry EXIF metadata including **GPS coordinates**. An employee
photographing their Aadhaar at home would otherwise hand you their home address
in the file metadata — data you never asked for and must not hold.

Orientation is applied first (so the image is upright), then *all* metadata is
discarded during re-encoding.
"""

from __future__ import annotations

import hashlib
import io
from typing import TYPE_CHECKING

from PIL import Image, ImageOps, UnidentifiedImageError

from avs.contracts import CaptureMethod, ErrorCode, ValidatedImage
from avs.ingest.errors import IngestError
from avs.ingest.magic import FileKind, detect

if TYPE_CHECKING:
    from avs.ingest.scanner import MalwareScanner

__all__ = ["HEIF_AVAILABLE", "ImageIngestor"]


# HEIF support is optional. Modern iPhones default to HEIC, so this matters in
# practice — but a missing codec must degrade to a clear message, never a crash.
try:  # pragma: no cover - depends on the deployment image
    import pillow_heif

    pillow_heif.register_heif_opener()
    HEIF_AVAILABLE = True
except Exception:
    HEIF_AVAILABLE = False


#: Pillow's own decompression-bomb guard. Set explicitly rather than relying on
#: the library default, which changes between versions.
_PILLOW_MAX_PIXELS = 100_000_000
Image.MAX_IMAGE_PIXELS = _PILLOW_MAX_PIXELS

#: Formats Pillow may report for input we accept. Used to cross-check the magic
#: bytes against what the decoder actually thinks it is opening.
_PILLOW_FORMAT_TO_KIND = {
    "JPEG": FileKind.JPEG,
    "MPO": FileKind.JPEG,  # multi-picture JPEG, produced by some phone cameras
    "PNG": FileKind.PNG,
    "WEBP": FileKind.WEBP,
    "HEIF": FileKind.HEIF,
    "HEIC": FileKind.HEIF,
    "AVIF": FileKind.HEIF,
}


class ImageIngestor:
    """Validates and normalises an uploaded image.

    Example:
        >>> ingestor = ImageIngestor()
        >>> image = ingestor.ingest(raw_bytes, filename="card.jpg")
        >>> image.width, image.height, image.mime_type
    """

    def __init__(
        self,
        *,
        min_bytes: int = 50 * 1024,
        max_bytes: int = 20 * 1024 * 1024,
        min_width: int = 640,
        min_height: int = 480,
        max_dimension: int = 12_000,
        max_pixels: int = 80_000_000,
        max_pixels_per_byte: float = 150.0,
        scanner: MalwareScanner | None = None,
        strip_metadata: bool = True,
    ) -> None:
        """
        Args:
            min_bytes: below this an image is too small to hold a readable Secure
                QR. Rejecting early saves the user a pointless failure downstream.
            max_bytes: upper bound on upload size.
            min_width/min_height: the Secure QR is dense; below roughly VGA it
                will not decode from a photograph.
            max_dimension: guards against absurd single-axis sizes.
            max_pixels: total-pixel ceiling. 80MP covers 108MP phone sensors
                after typical downscaling.
            max_pixels_per_byte: decompression-bomb heuristic. A file that
                expands to far more pixels than its byte count can justify is
                almost certainly crafted. Real photographs sit well under 40.
            scanner: optional malware scanner. When None, scanning is skipped.
            strip_metadata: discard EXIF (including GPS) during normalisation.
                Leave enabled unless you have a specific reason not to.
        """
        self.min_bytes = min_bytes
        self.max_bytes = max_bytes
        self.min_width = min_width
        self.min_height = min_height
        self.max_dimension = max_dimension
        self.max_pixels = max_pixels
        self.max_pixels_per_byte = max_pixels_per_byte
        self.scanner = scanner
        self.strip_metadata = strip_metadata

    # ------------------------------------------------------------------ #

    def ingest(
        self,
        data: bytes,
        filename: str | None = None,
        capture_method: CaptureMethod = CaptureMethod.UNKNOWN,
    ) -> ValidatedImage:
        """Validate, normalise, and hash an uploaded image.

        The ``filename`` is used only for error messages. It never influences
        type detection — see ``avs.ingest.magic``.

        Raises:
            IngestError: with an ErrorCode from the ingest family.
        """
        original_size = len(data)

        # Upper bound first — an oversized upload must not be held in memory a
        # moment longer than necessary.
        self._check_upper_size(original_size)

        # Type detection before the *lower* bound, deliberately. Magic-byte
        # sniffing reads 512 bytes and compares constants; it is not a parser and
        # costs nothing. Doing it first means a 4 KB executable renamed to .jpg
        # is reported as "this file is not an image" rather than the misleading
        # "image too small" — while decoders still stay strictly downstream.
        detected = self._check_type(data)

        self._check_lower_size(original_size)
        self._scan(data)

        image = self._open_header(data, detected)
        try:
            width, height = image.size
            self._check_dimensions(width, height, original_size)
            normalised, mime_type = self._normalise(image, detected)
        finally:
            image.close()

        # Hash the ORIGINAL bytes, not the normalised ones. This is the audit
        # identity of what the employee actually uploaded, and it stays stable
        # across Pillow versions — a normalised hash would not.
        digest = hashlib.sha256(data).hexdigest()

        with Image.open(io.BytesIO(normalised)) as final:
            final_width, final_height = final.size

        return ValidatedImage(
            data=normalised,
            mime_type=mime_type,
            width=final_width,
            height=final_height,
            size_bytes=original_size,
            sha256=digest,
            capture_method=capture_method,
        )

    # ------------------------------------------------------------------ #
    # 1. Size — cheapest possible check, no parsing
    # ------------------------------------------------------------------ #

    def _check_upper_size(self, size: int) -> None:
        """Runs first — an oversized upload is a resource problem, not a content one."""
        if size == 0:
            raise IngestError(ErrorCode.CORRUPT_IMAGE, "file is empty", "The file is empty.")
        if size > self.max_bytes:
            raise IngestError(
                ErrorCode.FILE_TOO_LARGE,
                f"{size} bytes exceeds the {self.max_bytes} byte maximum",
                f"This file is larger than {self.max_bytes // (1024 * 1024)} MB. "
                "Please upload a smaller photo.",
            )

    def _check_lower_size(self, size: int) -> None:
        """Runs after type detection, so we only tell a genuine image that it is
        too small — never a disguised executable."""
        if size < self.min_bytes:
            raise IngestError(
                ErrorCode.FILE_TOO_SMALL,
                f"{size} bytes is below the {self.min_bytes} byte minimum",
                "This image is too small to read the QR code. Please upload a "
                "full-resolution photo rather than a thumbnail or screenshot.",
            )

    # ------------------------------------------------------------------ #
    # 2-3. Type detection and allow-list — still no decoder involved
    # ------------------------------------------------------------------ #

    def _check_type(self, data: bytes) -> FileKind:
        detected = detect(data)

        if not detected.is_accepted:
            raise IngestError(
                ErrorCode.UNSUPPORTED_MIME_TYPE,
                f"detected {detected.kind.value}"
                + (f" ({detected.detail})" if detected.detail else ""),
                detected.kind.rejection_reason,
            )

        if detected.kind is FileKind.HEIF and not HEIF_AVAILABLE:
            raise IngestError(
                ErrorCode.UNSUPPORTED_MIME_TYPE,
                "HEIF codec not installed (pillow-heif missing)",
                "HEIC photos are not supported on this server. On iPhone, either "
                "change Settings → Camera → Formats to 'Most Compatible', or "
                "share the photo as JPEG.",
            )

        return detected.kind

    # ------------------------------------------------------------------ #
    # 4. Malware scan — on the original bytes, before any decode
    # ------------------------------------------------------------------ #

    def _scan(self, data: bytes) -> None:
        if self.scanner is None:
            return
        result = self.scanner.scan(data)
        if not result.clean:
            raise IngestError(
                ErrorCode.MALWARE_DETECTED,
                f"malware scan flagged: {result.signature or 'unknown signature'}",
                "This file was rejected by a security scan. Please upload a "
                "photo taken directly with your camera.",
            )

    # ------------------------------------------------------------------ #
    # 5. Header read — dimensions WITHOUT decoding pixel data
    # ------------------------------------------------------------------ #

    def _open_header(self, data: bytes, expected: FileKind) -> Image.Image:
        """``Image.open`` is lazy: it parses the header and stops.

        ``image.size`` is therefore available before a single pixel is decoded,
        which is exactly what the bomb guards need.
        """
        try:
            image = Image.open(io.BytesIO(data))
        except UnidentifiedImageError as exc:
            raise IngestError(
                ErrorCode.CORRUPT_IMAGE,
                f"decoder could not identify the image: {exc}",
                "This image appears to be damaged. Please take a new photo.",
            ) from exc
        except Image.DecompressionBombError as exc:
            raise IngestError(
                ErrorCode.DECOMPRESSION_BOMB,
                f"Pillow decompression bomb guard: {exc}",
                "This image could not be processed. Please take a new photo.",
            ) from exc
        except (OSError, ValueError) as exc:
            raise IngestError(
                ErrorCode.CORRUPT_IMAGE,
                f"failed to open image: {exc}",
                "This image appears to be damaged. Please take a new photo.",
            ) from exc

        actual_format = image.format or "UNKNOWN"
        actual_kind = _PILLOW_FORMAT_TO_KIND.get(actual_format.upper())

        # The header said one thing and the decoder read another. Either the file
        # is corrupt or someone is probing for a parser confusion bug. Refuse.
        if actual_kind is not expected:
            image.close()
            raise IngestError(
                ErrorCode.CORRUPT_IMAGE,
                f"magic bytes indicate {expected.value} but the decoder read {actual_format}",
                "This image appears to be damaged. Please take a new photo.",
            )

        return image

    # ------------------------------------------------------------------ #
    # 6. Bomb guards — using header dimensions only
    # ------------------------------------------------------------------ #

    def _check_dimensions(self, width: int, height: int, size_bytes: int) -> None:
        if width <= 0 or height <= 0:
            raise IngestError(
                ErrorCode.DIMENSIONS_INVALID,
                f"invalid dimensions {width}x{height}",
                "This image appears to be damaged. Please take a new photo.",
            )

        if width > self.max_dimension or height > self.max_dimension:
            raise IngestError(
                ErrorCode.DIMENSIONS_INVALID,
                f"{width}x{height} exceeds the {self.max_dimension}px limit",
                "This image is unusually large. Please upload a normal camera photo.",
            )

        pixels = width * height
        if pixels > self.max_pixels:
            raise IngestError(
                ErrorCode.DECOMPRESSION_BOMB,
                f"{pixels:,} pixels exceeds the {self.max_pixels:,} limit",
                "This image could not be processed. Please take a new photo.",
            )

        # A small file that claims an enormous canvas is the classic bomb shape:
        # a highly compressible image (solid colour, repeated rows) that expands
        # to gigabytes of RAM on decode. Real photographs never look like this.
        if size_bytes > 0 and (pixels / size_bytes) > self.max_pixels_per_byte:
            raise IngestError(
                ErrorCode.DECOMPRESSION_BOMB,
                f"{pixels:,} pixels from {size_bytes:,} bytes "
                f"({pixels / size_bytes:.0f} px/byte) — compression ratio implies a bomb",
                "This image could not be processed. Please take a new photo.",
            )

        if width < self.min_width or height < self.min_height:
            raise IngestError(
                ErrorCode.DIMENSIONS_INVALID,
                f"{width}x{height} is below the {self.min_width}x{self.min_height} minimum",
                "This image is too small to read the QR code. Please move closer "
                "to the card and take a full-resolution photo.",
            )

    # ------------------------------------------------------------------ #
    # 7. Decode and normalise — the first and only full decode
    # ------------------------------------------------------------------ #

    def _normalise(self, image: Image.Image, kind: FileKind) -> tuple[bytes, str]:
        """Apply EXIF orientation, convert HEIF to JPEG, and strip all metadata."""
        try:
            # Rotate to the orientation the photographer saw, using the EXIF tag,
            # BEFORE that tag is discarded.
            oriented = ImageOps.exif_transpose(image) or image

            if kind is FileKind.PNG:
                out_format, mime_type = "PNG", "image/png"
                if oriented.mode not in {"RGB", "RGBA", "L"}:
                    oriented = oriented.convert("RGBA")
            elif kind is FileKind.WEBP:
                out_format, mime_type = "WEBP", "image/webp"
                if oriented.mode not in {"RGB", "RGBA"}:
                    oriented = oriented.convert("RGB")
            else:
                # JPEG, and HEIF normalised to JPEG so every downstream stage
                # deals with one predictable codec.
                out_format, mime_type = "JPEG", "image/jpeg"
                if oriented.mode != "RGB":
                    oriented = oriented.convert("RGB")

            buffer = io.BytesIO()
            save_args: dict[str, object] = {"format": out_format}
            if out_format == "JPEG":
                # Quality 95 preserves the fine QR module edges that decoding
                # depends on. Lower settings visibly damage dense QR codes.
                save_args.update(quality=95, subsampling=0, optimize=True)
            elif out_format == "WEBP":
                save_args.update(quality=95, method=4)

            if self.strip_metadata:
                # A fresh canvas carries no ``info`` dict. ``paste`` copies pixel
                # data only, so every metadata block — EXIF, GPS, ICC, XMP,
                # thumbnails — is left behind by construction rather than by
                # remembering to exclude each one.
                clean = Image.new(oriented.mode, oriented.size)
                clean.paste(oriented)
                clean.save(buffer, **save_args)  # type: ignore[arg-type]
                clean.close()
            else:
                # Forensic mode. Carry the original EXIF through explicitly.
                exif_bytes = oriented.info.get("exif") or image.info.get("exif")
                if exif_bytes and out_format == "JPEG":
                    save_args["exif"] = exif_bytes
                oriented.save(buffer, **save_args)  # type: ignore[arg-type]

            if oriented is not image:
                oriented.close()

            return buffer.getvalue(), mime_type

        except Image.DecompressionBombError as exc:
            raise IngestError(
                ErrorCode.DECOMPRESSION_BOMB,
                f"decompression bomb during decode: {exc}",
                "This image could not be processed. Please take a new photo.",
            ) from exc
        except (OSError, ValueError, MemoryError) as exc:
            raise IngestError(
                ErrorCode.CORRUPT_IMAGE,
                f"failed to decode image: {exc}",
                "This image appears to be damaged. Please take a new photo.",
            ) from exc
