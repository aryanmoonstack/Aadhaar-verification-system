"""Synthetic image generation for ingest tests — fixtures only.

⛔ NOT PRODUCTION CODE. No real Aadhaar image is ever used.

Every image here is generated from noise or flat colour. That is sufficient for
Step 3, which validates *containers* — size, type, dimensions, metadata — and
never looks at what the picture depicts.
"""

from __future__ import annotations

import io
import os

from PIL import Image

__all__ = [
    "FAKE_HEADERS",
    "corrupt_bytes",
    "make_bomb_png",
    "make_exif_jpeg",
    "make_image_bytes",
    "make_noise_image",
]


def make_noise_image(width: int = 800, height: int = 600) -> Image.Image:
    """Random pixels — incompressible, so file size stays realistic.

    A flat-colour image compresses so well that it trips the decompression-bomb
    heuristic. That is correct behaviour, but useless as a "valid photo" fixture,
    so real fixtures use noise.
    """
    return Image.frombytes("RGB", (width, height), os.urandom(width * height * 3))


def make_image_bytes(
    width: int = 800,
    height: int = 600,
    fmt: str = "JPEG",
    *,
    quality: int = 92,
    noise: bool = True,
) -> bytes:
    image = (
        make_noise_image(width, height)
        if noise
        else Image.new("RGB", (width, height), (128, 128, 128))
    )
    buffer = io.BytesIO()
    if fmt.upper() == "JPEG":
        image.save(buffer, format="JPEG", quality=quality)
    elif fmt.upper() == "PNG":
        image.save(buffer, format="PNG")
    elif fmt.upper() == "WEBP":
        image.save(buffer, format="WEBP", quality=quality)
    else:
        image.save(buffer, format=fmt)
    image.close()
    return buffer.getvalue()


def make_bomb_png(width: int = 6000, height: int = 6000) -> bytes:
    """A flat-colour PNG: tiny on disk, enormous in memory.

    This is the classic decompression-bomb shape — the file is a few dozen
    kilobytes but decoding it allocates hundreds of megabytes.
    """
    image = Image.new("RGB", (width, height), (255, 255, 255))
    buffer = io.BytesIO()
    image.save(buffer, format="PNG", optimize=True)
    image.close()
    return buffer.getvalue()


def make_exif_jpeg(
    width: int = 800,
    height: int = 600,
    *,
    orientation: int = 1,
    with_gps: bool = True,
) -> bytes:
    """A JPEG carrying EXIF, optionally including GPS coordinates.

    Phone cameras embed GPS by default. These fixtures prove the pipeline
    discards it.
    """
    image = make_noise_image(width, height)
    exif = Image.Exif()
    exif[0x0112] = orientation  # Orientation
    exif[0x010F] = "TestPhone"  # Make
    exif[0x0110] = "TestModel"  # Model
    exif[0x0132] = "2026:08:13 10:30:00"  # DateTime

    if with_gps:
        exif[0x8825] = {
            1: "N",
            2: (26.0, 54.0, 0.0),  # Jaipur, roughly
            3: "E",
            4: (75.0, 49.0, 0.0),
        }

    buffer = io.BytesIO()
    image.save(buffer, format="JPEG", quality=92, exif=exif)
    image.close()
    return buffer.getvalue()


def corrupt_bytes(data: bytes, start: int = 200, length: int = 400) -> bytes:
    """Keep a valid header, destroy the body — a truncated or damaged upload."""
    corrupted = bytearray(data)
    end = min(start + length, len(corrupted))
    for index in range(start, end):
        corrupted[index] = 0x00
    return bytes(corrupted)


#: Minimal headers for file types the pipeline must recognise and refuse.
#: Padded so they clear the minimum-size check and reach type detection.
FAKE_HEADERS: dict[str, bytes] = {
    "pdf": b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n" + b"0" * 4000,
    "zip": b"PK\x03\x04\x14\x00\x00\x00\x08\x00" + b"0" * 4000,
    "gzip": b"\x1f\x8b\x08\x00\x00\x00\x00\x00" + b"0" * 4000,
    "elf": b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00" + b"0" * 4000,
    "pe": b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00" + b"0" * 4000,
    "javaclass": b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"0" * 4000,
    "gif": b"GIF89a\x01\x00\x01\x00\x00\x00\x00" + b"0" * 4000,
    "bmp": b"BM\x36\x00\x00\x00\x00\x00\x00\x00" + b"0" * 4000,
    "tiff": b"II*\x00\x08\x00\x00\x00\x00\x00\x00\x00" + b"0" * 4000,
    "svg": b'<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>' + b" " * 4000,
    "html": b"<!DOCTYPE html><html><body>hello</body></html>" + b" " * 4000,
    "random": bytes(range(256)) * 20,
}
