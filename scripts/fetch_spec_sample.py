#!/usr/bin/env python3
"""Fetch UIDAI's published Secure QR sample payload for conformance testing.

    python scripts/fetch_spec_sample.py

UIDAI publishes a complete sample Secure QR payload inside its specification
PDF. Running our parser against it is the only check we have that is genuinely
independent of our own assumptions — every other test builds its input with
`SyntheticQrBuilder`, which was written from the same understanding as the
parser and therefore agreed with it even when both were wrong.

⛔ THE SAMPLE IS NEVER COMMITTED.
   It decodes to a person's demographics and photograph. UIDAI published it, but
   this repository's rule does not bend: no Aadhaar payload enters git. The file
   lands in `tests/fixtures/local/`, which is git-ignored.

Source:
    UIDAI, "SECURE QR CODE SPECIFICATION", March 2019
    https://uidai.gov.in/images/resource/User_manulal_QR_Code_15032019.pdf
"""

from __future__ import annotations

import re
from pathlib import Path

SPEC_URL = "https://uidai.gov.in/images/resource/User_manulal_QR_Code_15032019.pdf"
TARGET = Path("tests/fixtures/local/spec_sample.txt")

#: The sample is one enormous decimal integer. Anything shorter is not it.
MIN_SAMPLE_DIGITS = 2000


def main() -> int:
    try:
        import httpx
    except ImportError:
        print('httpx is not installed.  pip install -e ".[service]"')
        return 1

    try:
        from pypdf import PdfReader
    except ImportError:
        print("pypdf is not installed.  pip install pypdf")
        print("\nAlternatively, download the PDF yourself, copy the sample number")
        print(f"from the 'Sample Data' section, and save it to {TARGET}")
        return 1

    print(f"Fetching {SPEC_URL}")
    try:
        response = httpx.get(SPEC_URL, timeout=60.0, follow_redirects=True)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        print(f"Could not fetch the specification: {exc}")
        print(f"\nDownload it manually, copy the sample number, save to {TARGET}")
        return 1

    import io

    reader = PdfReader(io.BytesIO(response.content))
    text = "\n".join(page.extract_text() or "" for page in reader.pages)

    # The sample is printed across many wrapped lines. Strip whitespace inside
    # every run of digits and keep the longest — the payload dwarfs every page
    # number, date and section reference in the document.
    pattern = rf"(?:\d[\s\n]*){{{MIN_SAMPLE_DIGITS},}}"
    candidates = re.findall(pattern, text)
    if not candidates:
        print("No sample payload found in the PDF — the document layout may have changed.")
        print(f"Copy it manually from the 'Sample Data' section into {TARGET}")
        return 1

    sample = re.sub(r"\s+", "", max(candidates, key=len))
    if not sample.isdigit() or len(sample) < MIN_SAMPLE_DIGITS:
        print(f"Extracted {len(sample)} characters but they are not a plausible payload.")
        return 1

    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_text(sample, encoding="utf-8")

    print(f"\nWrote {len(sample)} digits to {TARGET}")
    print("This file is git-ignored and must stay that way.")
    print("\nNow run:  python -m pytest tests/unit/test_uidai_spec_conformance.py -v")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
