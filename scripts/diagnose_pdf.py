#!/usr/bin/env python3
"""Why did this PDF not verify? Answers it without the file leaving your machine.

    python scripts/diagnose_pdf.py C:\\aadhaar-corpus\\pdfs --password AARY1999

★ THE QUESTION THIS EXISTS TO SETTLE

  A `LEGACY_FORMAT` verdict says "the QR we read was a pre-2018 XML code". It
  does NOT say whether a Secure QR was also present and simply failed to decode.

  Those two need opposite responses. A genuinely old e-Aadhaar means telling the
  employee to download a fresh one. A Secure QR that rendered too small means
  raising the render resolution — and telling that employee to re-download would
  be useless advice, because the new file would fail identically.

  So this renders every page at several resolutions and reports every QR it can
  find at each. If a Secure QR appears at 400 or 600 DPI but not at 300, the
  answer is DPI, not the document.

⛔ PRIVACY — WHAT THIS PRINTS AND WHAT IT NEVER PRINTS

   Printed: how many QRs, what KIND each is, how many characters long, and the
   character class. Those are shapes.

   Never printed: any part of a payload, any name, any date of birth, any digits
   from an Aadhaar number. The output is designed to be safe to paste into a
   chat or an email, because that is exactly what happens to diagnostics.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

#: Rendered resolutions to compare. 300 is the production default.
#:
#: ⚠ The Secure QR is far denser than the legacy one — roughly 97 modules across
#:   versus about 30 — so it needs several times the pixels to survive. A page
#:   where only the legacy code decodes is exactly what "too few pixels per
#:   module" looks like from the outside.
DPIS = (300, 400, 600)


def looks_like_a_pdf(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(5) == b"%PDF-"
    except OSError:
        return False


def describe(text: str) -> str:
    """A payload's SHAPE. Never its content.

    ⛔ Every branch returns a category and a length. Nothing here can emit a
       character of the payload, which is the property that makes the output
       safe to share.
    """
    stripped = text.strip()
    size = len(stripped)

    if size >= 100 and stripped.isdigit():
        return f"SECURE_QR      {size:>6} digits   ← the signed payload"
    if stripped.isdigit():
        return f"digits         {size:>6} digits   ← too short for a Secure QR"

    head = stripped[:200].lstrip().lower()
    if head.startswith("<?xml") or "printletterbarcodedata" in head or "uid=" in head:
        return f"LEGACY_XML     {size:>6} chars    ← pre-2018, cannot be signed"
    if stripped.startswith(("http://", "https://")):
        return f"URL            {size:>6} chars    ← a link, not an Aadhaar code"
    return f"other          {size:>6} chars"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path, help="Folder of PDFs (stays local)")
    parser.add_argument("--password", default=None)
    parser.add_argument(
        "--dpi",
        type=int,
        nargs="*",
        default=list(DPIS),
        help="Resolutions to compare. Default: 300 400 600",
    )
    arguments = parser.parse_args()

    if arguments.password and arguments.password.upper() in {
        "YOUR_ACTUAL_PASSWORD",
        "YOUR_PASSWORD",
        "YOURPASSWORD",
        "PASSWORD",
    }:
        print(f"⛔ That is the example password, not a real one: {arguments.password}")
        return 2

    if not arguments.folder.is_dir():
        print(f"⛔ No such folder: {arguments.folder}")
        return 2

    try:
        import zxingcpp
    except ImportError:
        print("⛔ zxing-cpp is not installed:  pip install zxing-cpp")
        return 2

    from PIL import Image

    from avs.ingest.errors import IngestError
    from avs.ingest.pdf import PDFIUM_AVAILABLE, render_pdf

    if not PDFIUM_AVAILABLE:
        print("⛔ pypdfium2 is not installed:  pip install pypdfium2")
        return 2

    pdfs = sorted(p for p in arguments.folder.rglob("*") if p.is_file() and looks_like_a_pdf(p))
    if not pdfs:
        print(f"⛔ No PDFs under {arguments.folder}")
        return 1

    print(f"\n{len(pdfs)} PDF(s). Rendering at {', '.join(str(d) for d in arguments.dpi)} DPI.\n")

    found_secure_only_at_high_dpi = False

    for index, path in enumerate(pdfs, start=1):
        # ⛔ The INDEX, never the filename. Filenames routinely contain a real
        #    person's name, and this output is meant to be pasteable.
        print(f"── PDF {index} " + "─" * 60)
        data = path.read_bytes()
        print(f"   {len(data):,} bytes")

        secure_by_dpi: dict[int, bool] = {}

        for dpi in arguments.dpi:
            try:
                pages = render_pdf(data, password=arguments.password, dpi=dpi)
            except IngestError as exc:
                print(f"   {dpi} DPI: ⛔ {exc.code.value}")
                if exc.code.value.startswith("PDF_PASSWORD"):
                    print("            (supply --password, or the right one)")
                secure_by_dpi[dpi] = False
                break

            secure_found = False
            for page in pages:
                with Image.open(__import__("io").BytesIO(page.data)) as image:
                    codes = zxingcpp.read_barcodes(image)

                if not codes:
                    print(f"   {dpi} DPI  page {page.page_number}: no QR found "
                          f"({page.width}x{page.height})")
                    continue

                for code in codes:
                    shape = describe(code.text)
                    if shape.startswith("SECURE_QR"):
                        secure_found = True
                    print(f"   {dpi} DPI  page {page.page_number}: {shape}")

            secure_by_dpi[dpi] = secure_found

        # ★ The comparison that answers the question.
        low = arguments.dpi[0]
        if not secure_by_dpi.get(low, False):
            higher = [d for d in arguments.dpi[1:] if secure_by_dpi.get(d)]
            if higher:
                found_secure_only_at_high_dpi = True
                print(f"\n   ★ A Secure QR decodes at {higher[0]} DPI but NOT at {low}.")
                print(f"      This document is fine — the render resolution is too low.")
            else:
                print(f"\n   → No Secure QR at any resolution tried.")
                print("      This looks like a genuinely pre-2018 e-Aadhaar. The right")
                print("      answer is LEGACY_FORMAT: ask for a freshly downloaded one.")
        print()

    print("=" * 68)
    if found_secure_only_at_high_dpi:
        print("⛔ ACTION: raise `pdf_render_dpi`. At least one document carries a")
        print("   Secure QR that the production 300 DPI render cannot resolve.")
    else:
        print("No resolution problem found. Verdicts reflect the documents.")
    print("=" * 68)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
