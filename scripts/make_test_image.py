#!/usr/bin/env python3
"""Generate test images for the Step 3 ingest boundary — no real document needed.

Produces a small set of files that exercise the interesting paths:

    test-images/
    ├── photo_with_gps.jpg   valid JPEG carrying EXIF + GPS + rotation tag
    ├── disguised.jpg        a Windows executable renamed to .jpg
    ├── document.pdf         a PDF (rejected — this project is images-only)
    └── bomb.png             6000x6000 flat colour: ~120 KB on disk, ~108 MB decoded

Then try each:

    avs ingest test-images\\photo_with_gps.jpg
    avs ingest test-images\\disguised.jpg
    avs ingest test-images\\document.pdf
    avs ingest test-images\\bomb.png

The first is accepted — note that it comes back rotated (EXIF orientation
applied) with all metadata gone. The other three are refused, each naming the
real problem rather than a generic error.

Usage:
    python scripts/make_test_image.py [output-dir]
"""

from __future__ import annotations

import io
import os
import sys
from pathlib import Path

from PIL import Image


def make_photo_with_gps(path: Path) -> None:
    """A realistic phone photo: noise pixels, EXIF, GPS, and a rotation tag."""
    image = Image.frombytes("RGB", (1200, 900), os.urandom(1200 * 900 * 3))

    exif = Image.Exif()
    exif[0x0112] = 6  # Orientation: rotate 90° — output should be 900x1200
    exif[0x010F] = "TestPhone"
    exif[0x0110] = "TestModel X"
    exif[0x0132] = "2026:08:13 10:30:00"
    exif[0x8825] = {  # GPS — this is what must not survive
        1: "N",
        2: (26.0, 54.0, 0.0),  # Jaipur, roughly
        3: "E",
        4: (75.0, 49.0, 0.0),
    }

    buffer = io.BytesIO()
    image.save(buffer, format="JPEG", quality=92, exif=exif)
    image.close()
    path.write_bytes(buffer.getvalue())


def make_disguised_executable(path: Path) -> None:
    """A DOS/PE binary with a .jpg extension.

    Extensions are a claim by the uploader. Magic bytes are evidence.
    """
    path.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00" + os.urandom(80_000))


def make_pdf(path: Path) -> None:
    path.write_bytes(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n" + b"0" * 80_000)


def make_bomb(path: Path) -> None:
    """Flat colour at 6000x6000 — tiny compressed, enormous decoded."""
    image = Image.new("RGB", (6000, 6000), (255, 255, 255))
    buffer = io.BytesIO()
    image.save(buffer, format="PNG", optimize=True)
    image.close()
    path.write_bytes(buffer.getvalue())


def main() -> int:
    out_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "test-images")
    out_dir.mkdir(parents=True, exist_ok=True)

    builders = [
        ("photo_with_gps.jpg", make_photo_with_gps, "valid — EXIF + GPS + rotation"),
        ("disguised.jpg", make_disguised_executable, "executable renamed .jpg"),
        ("document.pdf", make_pdf, "PDF — out of scope"),
        ("bomb.png", make_bomb, "decompression bomb"),
    ]

    print(f"Writing to {out_dir.resolve()}\n")
    for name, build, description in builders:
        path = out_dir / name
        build(path)
        print(f"  {name:<22} {path.stat().st_size:>9,} bytes   {description}")

    print("\nNow try:")
    for name, _, _ in builders:
        print(f"  avs ingest {out_dir}{os.sep}{name}")
    print(
        "\nThe first is accepted — check that it comes back rotated and that\n"
        "the GPS coordinates are gone. The rest are refused, each naming the\n"
        "actual problem rather than a generic error."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
