"""Magic-byte file type detection — Step 3.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 3
Provides : detect(bytes) -> DetectedType, FileKind
Consumes : nothing (pure stdlib — deliberately no third-party parser)
Used by  : avs.ingest.validator

WHY WE NEVER TRUST THE FILE EXTENSION
-------------------------------------
An extension is a claim made by whoever uploaded the file. A Windows executable
renamed ``aadhaar.jpg`` is still an executable; a ZIP renamed ``card.png`` is
still a ZIP. Extensions are metadata, not evidence.

Magic bytes are the file's own self-description at offset zero, written by
whatever produced it. That is evidence.

This module is deliberately pure stdlib. It runs *before* any decoder touches
the bytes, so it must not itself be a parser with an attack surface. It reads a
few dozen bytes and compares them to known signatures. That is all it does.

Detecting a *disallowed* type precisely still matters: telling an employee
"PDF is not supported, please photograph the card" is a far better experience
than a generic rejection — and telling ops "that was a ZIP archive" is far more
useful than "invalid file".
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

__all__ = ["ALLOWED_MIME_TYPES", "DetectedType", "FileKind", "detect"]


class FileKind(str, Enum):
    """What the bytes actually are, regardless of what the filename claims."""

    # Accepted
    JPEG = "jpeg"
    PNG = "png"
    WEBP = "webp"
    HEIF = "heif"

    # Images we recognise but do not accept
    GIF = "gif"
    BMP = "bmp"
    TIFF = "tiff"

    # Explicitly named so the user gets a useful message
    PDF = "pdf"

    # Actively dangerous
    ZIP = "zip"  # also .docx / .xlsx / .jar
    EXECUTABLE = "executable"
    SCRIPT = "script"  # SVG / HTML — script-bearing markup

    UNKNOWN = "unknown"

    @property
    def mime_type(self) -> str:
        return {
            FileKind.JPEG: "image/jpeg",
            FileKind.PNG: "image/png",
            FileKind.WEBP: "image/webp",
            FileKind.HEIF: "image/heif",
            FileKind.GIF: "image/gif",
            FileKind.BMP: "image/bmp",
            FileKind.TIFF: "image/tiff",
            FileKind.PDF: "application/pdf",
            FileKind.ZIP: "application/zip",
            FileKind.EXECUTABLE: "application/octet-stream",
            FileKind.SCRIPT: "text/xml",
        }.get(self, "application/octet-stream")

    @property
    def is_accepted(self) -> bool:
        return self in {FileKind.JPEG, FileKind.PNG, FileKind.WEBP, FileKind.HEIF}

    @property
    def rejection_reason(self) -> str:
        """A message an employee can act on, not a stack trace."""
        return {
            FileKind.PDF: (
                "PDF files are not supported. Please upload a photo or scan of "
                "your Aadhaar card as an image."
            ),
            FileKind.GIF: "GIF images are not supported. Please upload a JPEG or PNG photo.",
            FileKind.BMP: "BMP images are not supported. Please upload a JPEG or PNG photo.",
            FileKind.TIFF: "TIFF images are not supported. Please upload a JPEG or PNG photo.",
            FileKind.ZIP: "This is an archive, not an image. Please upload a photo of your card.",
            FileKind.EXECUTABLE: "This file is not an image.",
            FileKind.SCRIPT: "This file is not an image.",
            FileKind.UNKNOWN: (
                "This file could not be recognised as an image. Please upload a "
                "JPEG, PNG, HEIC or WebP photo."
            ),
        }.get(self, "This file type is not supported.")


#: MIME types the pipeline accepts. Mirrors CONTRACTS.md §9.
ALLOWED_MIME_TYPES: frozenset[str] = frozenset(
    {"image/jpeg", "image/png", "image/webp", "image/heif", "image/heic"}
)


@dataclass(frozen=True, slots=True)
class DetectedType:
    kind: FileKind
    mime_type: str
    detail: str = ""

    @property
    def is_accepted(self) -> bool:
        return self.kind.is_accepted


# --------------------------------------------------------------------------- #
# Signatures
# --------------------------------------------------------------------------- #

#: ISO-BMFF brands that indicate HEIF/HEIC still images.
_HEIF_BRANDS = frozenset(
    {
        b"heic",
        b"heix",
        b"heim",
        b"heis",
        b"hevc",
        b"hevx",
        b"hevm",
        b"hevs",
        b"mif1",
        b"msf1",
        b"avif",  # AVIF shares the container; Pillow may still refuse it
    }
)

_MINIMUM_HEADER_BYTES = 12


def detect(data: bytes) -> DetectedType:
    """Identify a file from its leading bytes.

    Never raises. Unrecognised input returns ``FileKind.UNKNOWN`` rather than an
    exception, because "I don't know what this is" is a normal outcome that the
    caller turns into a friendly rejection.
    """
    if len(data) < _MINIMUM_HEADER_BYTES:
        return DetectedType(FileKind.UNKNOWN, "application/octet-stream", "file too short")

    # ── Accepted image formats ────────────────────────────────────────────
    if data[:3] == b"\xff\xd8\xff":
        return DetectedType(FileKind.JPEG, "image/jpeg")

    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return DetectedType(FileKind.PNG, "image/png")

    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return DetectedType(FileKind.WEBP, "image/webp")

    # ISO base media container: [4-byte size]"ftyp"[4-byte brand]
    if data[4:8] == b"ftyp":
        brand = data[8:12]
        if brand in _HEIF_BRANDS:
            return DetectedType(FileKind.HEIF, "image/heif", brand.decode("ascii", "replace"))
        return DetectedType(
            FileKind.UNKNOWN,
            "application/octet-stream",
            f"unsupported ISO-BMFF brand {brand!r}",
        )

    # ── Recognised but not accepted ───────────────────────────────────────
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return DetectedType(FileKind.GIF, "image/gif")

    if data[:2] == b"BM":
        return DetectedType(FileKind.BMP, "image/bmp")

    if data[:4] in (b"II*\x00", b"MM\x00*"):
        return DetectedType(FileKind.TIFF, "image/tiff")

    if data[:5] == b"%PDF-":
        return DetectedType(FileKind.PDF, "application/pdf")

    # ── Dangerous ─────────────────────────────────────────────────────────
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return DetectedType(FileKind.ZIP, "application/zip", "ZIP container")

    if data[:4] == b"\x7fELF":
        return DetectedType(FileKind.EXECUTABLE, "application/x-executable", "ELF binary")

    if data[:2] == b"MZ":
        return DetectedType(FileKind.EXECUTABLE, "application/x-msdownload", "DOS/PE binary")

    if data[:4] == b"\xca\xfe\xba\xbe":
        return DetectedType(FileKind.EXECUTABLE, "application/java-vm", "Java class")

    if data[:2] in (b"\x1f\x8b", b"BZ") or data[:6] == b"\xfd7zXZ\x00":
        return DetectedType(FileKind.ZIP, "application/gzip", "compressed archive")

    # SVG and HTML can carry script. They are markup, not raster images.
    head = data[:512].lstrip().lower()
    if head.startswith(b"<?xml") or head.startswith(b"<svg") or b"<svg" in head[:200]:
        return DetectedType(FileKind.SCRIPT, "image/svg+xml", "SVG markup")
    if head.startswith(b"<!doctype html") or head.startswith(b"<html"):
        return DetectedType(FileKind.SCRIPT, "text/html", "HTML markup")

    return DetectedType(FileKind.UNKNOWN, "application/octet-stream")
