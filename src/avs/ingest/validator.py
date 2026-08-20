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
        pdf_render_dpi: int = 300,
        pdf_max_pixels_per_byte: float = 1000.0,
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
            pdf_render_dpi: resolution for rendering PDF pages. See
                ``avs.ingest.pdf.DEFAULT_RENDER_DPI`` for why 300 and not 150.
            pdf_max_pixels_per_byte: the bomb heuristic for *rendered pages*,
                which compress far better than photographs. Measured separately
                — see ``_pdf_page_ingestor``.
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
        self.pdf_render_dpi = pdf_render_dpi
        self.pdf_max_pixels_per_byte = pdf_max_pixels_per_byte

    # ------------------------------------------------------------------ #

    def ingest(
        self,
        data: bytes,
        filename: str | None = None,
        capture_method: CaptureMethod = CaptureMethod.UNKNOWN,
        password: str | None = None,
    ) -> ValidatedImage:
        """Validate, normalise, and hash one uploaded file.

        For a PDF this returns the **first** page. Callers that need every page
        — anything searching for a QR code — must use ``ingest_all`` instead,
        because the Secure QR is frequently not on page one.

        The ``filename`` is used only for error messages. It never influences
        type detection — see ``avs.ingest.magic``.

        Raises:
            IngestError: with an ErrorCode from the ingest family.
        """
        return self.ingest_all(data, filename, capture_method, password)[0]

    def ingest_all(
        self,
        data: bytes,
        filename: str | None = None,
        capture_method: CaptureMethod = CaptureMethod.UNKNOWN,
        password: str | None = None,
    ) -> list[ValidatedImage]:
        """Validate one upload and return every image it contains.

        An image yields a single-element list. A PDF yields one entry per
        rendered page, in document order.

        ★ This is the real entry point; ``ingest`` is a one-page convenience
          wrapper kept so existing callers did not have to change.

        Args:
            password: for an encrypted PDF. Ignored for images. Never logged.
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

        if detected is FileKind.PDF:
            # ⚠ The malware scan runs on the ORIGINAL PDF bytes, before the
            #   renderer parses them — same ordering rule as for an image, and it
            #   matters more here, since a PDF can carry embedded payloads that
            #   vanish once the page is rasterised.
            self._scan(data)
            return self._ingest_pdf(data, original_size, capture_method, password)

        # ⚠ The lower-size floor is deliberately NOT applied to a PDF. Its
        #   justification — "too few bytes to hold a readable QR" — is about
        #   photographs. A Secure QR stored as vector data renders perfectly from
        #   a 20 KB file, so the same floor would reject valid documents.
        self._check_lower_size(original_size)
        self._scan(data)

        return [self._ingest_image(data, detected, original_size, capture_method)]

    # ------------------------------------------------------------------ #

    def _ingest_image(
        self,
        data: bytes,
        detected: FileKind,
        reported_size: int,
        capture_method: CaptureMethod,
        identity_sha256: str | None = None,
    ) -> ValidatedImage:
        """The image path: header read, bomb guards, decode, normalise.

        Args:
            reported_size: the size recorded on the result. For a PDF page this
                is the size of the *source PDF*, not the rendered PNG — the
                audit trail should describe what the employee uploaded.
            identity_sha256: overrides the hash. Set for PDF pages so every page
                carries the digest of the original document rather than of a
                render, which is not reproducible across renderer versions.
        """
        original_size = len(data)
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
        digest = identity_sha256 or hashlib.sha256(data).hexdigest()

        with Image.open(io.BytesIO(normalised)) as final:
            final_width, final_height = final.size

        return ValidatedImage(
            data=normalised,
            mime_type=mime_type,
            width=final_width,
            height=final_height,
            size_bytes=reported_size or original_size,
            sha256=digest,
            capture_method=capture_method,
        )

    # ------------------------------------------------------------------ #
    # The PDF path — render, then rejoin the image path above
    # ------------------------------------------------------------------ #

    def _ingest_pdf(
        self,
        data: bytes,
        original_size: int,
        capture_method: CaptureMethod,
        password: str | None,
    ) -> list[ValidatedImage]:
        """Render every page, then validate each one as an ordinary image.

        ★ The rejoin is the point. Rendered pages go through exactly the same
          header read, bomb guards and metadata stripping as an uploaded JPEG.
          Nothing downstream of here knows a PDF was involved, and no guard had
          to be duplicated or relaxed to make that true.

        ⚠ Bomb guards are applied with PDF-specific limits. The photograph
          limits do not transfer — see ``_pdf_page_ingestor``.
        """
        from avs.ingest.pdf import render_pdf  # local: keeps pypdfium2 optional

        pages = render_pdf(data, password=password, dpi=self.pdf_render_dpi)

        # One identity for the whole document. Each page is a view of the same
        # uploaded file, so they share its digest rather than inventing one per
        # render — a render hash would change with the renderer version and
        # break duplicate detection silently.
        digest = hashlib.sha256(data).hexdigest()

        page_ingestor = self._pdf_page_ingestor()
        validated: list[ValidatedImage] = []
        failures: list[IngestError] = []

        for page in pages:
            try:
                validated.append(
                    page_ingestor._ingest_image(
                        page.data,
                        FileKind.PNG,
                        original_size,
                        capture_method,
                        identity_sha256=digest,
                    )
                )
            except IngestError as exc:
                # One unusable page does not condemn the document — the QR may
                # be on another one. Only an all-pages failure is fatal.
                exc.message = f"page {page.page_number}: {exc.message}"
                failures.append(exc)

        if not validated:
            raise self._pdf_failure(failures)

        return validated

    @staticmethod
    def _pdf_failure(failures: list[IngestError]) -> IngestError:
        """Collapse per-page failures into one error, keeping the code when it agrees.

        ⛔ Flattening everything to CORRUPT_IMAGE loses information that matters.
           A PDF whose pages all exceed the pixel ceiling is a decompression
           bomb; reporting it as "damaged PDF" files it under the wrong
           category, and an operator reading the audit trail would never see the
           attack. The specific code survives whenever every page agrees on it.
        """
        codes = {failure.code for failure in failures}
        detail = "; ".join(failure.message for failure in failures)

        if len(codes) == 1:
            single = failures[0]
            return IngestError(single.code, detail, single.user_message)

        return IngestError(
            ErrorCode.CORRUPT_IMAGE,
            f"no page of the PDF passed validation — {detail}",
            "This PDF could not be read. Please upload a photo of your "
            "Aadhaar card instead.",
        )

    def _pdf_page_ingestor(self) -> ImageIngestor:
        """A sibling ingestor with limits appropriate to a rendered page.

        ⛔ Two of the photograph limits are actively wrong for rendered pages,
           and both would reject valid documents:

           ``max_pixels_per_byte`` is a decompression-bomb heuristic tuned on
           camera photos, which are noisy and compress poorly. A rendered page is
           mostly flat white and compresses extremely well.

           Measured, A4 at 300 DPI (2481x3508, 8.7 MP):

               page content        PNG bytes     px/byte
               ---------------------------------------------
               near-blank             33,160       262.5   <- over the photo limit
               text only              54,567       159.5   <- over the photo limit
               text + Secure QR      142,752        61.0

           The photograph limit is 150. Two of those three valid pages exceed
           it, so keeping it would have rejected real e-Aadhaar documents —
           most likely a sparse second page, which is the hardest failure to
           reproduce and diagnose.

           1000 leaves roughly 4x headroom over the worst measured page. The
           guard is raised rather than removed, and it was never the real
           protection anyway: ``max_pixels`` bounds memory absolutely, and
           ``avs.ingest.pdf`` refuses a page over 40 MP before allocating the
           bitmap at all.

           ``min_bytes`` is about photographs holding enough detail to decode.
           It says nothing useful about a losslessly rendered page.
        """
        return ImageIngestor(
            min_bytes=1,
            max_bytes=self.max_bytes,
            min_width=self.min_width,
            min_height=self.min_height,
            max_dimension=self.max_dimension,
            max_pixels=self.max_pixels,
            max_pixels_per_byte=self.pdf_max_pixels_per_byte,
            scanner=None,  # already scanned, on the original PDF bytes
            strip_metadata=self.strip_metadata,
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
