"""Conformance to UIDAI's published Secure QR specification — Step 7.5.

⛔ WHY THIS FILE EXISTS

   Every other test in this suite builds its input with `SyntheticQrBuilder`.
   That fixture and the parser were written from the same understanding of the
   format — so when that understanding was wrong, they agreed with each other
   and both disagreed with reality. 540 tests passed while real Aadhaar cards
   failed to parse.

   A fixture derived from the code under test proves only self-consistency.
   This file is the antidote: it checks the parser against the layout UIDAI
   actually publishes, independent of anything we generate.

SOURCE OF TRUTH
---------------
    UIDAI, "SECURE QR CODE SPECIFICATION", March 2019, sections 2.2 and 3.1
    https://uidai.gov.in/images/resource/User_manulal_QR_Code_15032019.pdf

The specification also publishes a complete sample payload. Running the parser
against it is the strongest check available without a real card, and it is what
finally settled a three-round debugging cycle.

⚠ THE SAMPLE PAYLOAD IS NOT COMMITTED.
  It decodes to a person's demographics and photograph. Even though UIDAI
  published it, this repository's rule is absolute: no Aadhaar payload is ever
  committed. Fetch it locally to enable the sample test:

      python scripts/fetch_spec_sample.py

  Without it the layout tests below still run — they are the ones that catch
  drift. The sample test skips.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from avs.parser import SecureQrParser
from avs.parser.fields import FIELD_MAPS, detect_version, field_map_for

# --------------------------------------------------------------------------- #
# The specification, transcribed. UIDAI "SECURE QR CODE SPECIFICATION" §3.1.
# --------------------------------------------------------------------------- #

#: Verbatim field sequence. Note the address order is NOT the logical postal
#: order a developer would invent — care_of, district, landmark, house,
#: location, pincode, post_office, state, street, sub_district, vtc. Guessing it
#: would silently put the district in the house column on every card, and the
#: signature would still verify because it covers raw bytes.
UIDAI_FIELD_SEQUENCE = (
    "_presence",
    "reference_id",
    "name",
    "dob",
    "gender",
    "care_of",
    "district",
    "landmark",
    "house",
    "location",
    "pincode",
    "post_office",
    "state",
    "street",
    "sub_district",
    "vtc",
)

SPEC_SAMPLE = Path(os.environ.get("AVS_SPEC_SAMPLE", "tests/fixtures/local/spec_sample.txt"))


# --------------------------------------------------------------------------- #
# Layout conformance — always runs
# --------------------------------------------------------------------------- #


def test_v1_map_matches_the_uidai_specification_exactly():
    """★ The load-bearing assertion of this whole file.

    If this drifts, genuine cards get their fields silently mislabelled and the
    cryptography cannot catch it — the signature is over raw bytes and verifies
    regardless of how we name the pieces.
    """
    assert field_map_for("V1") == UIDAI_FIELD_SEQUENCE


def test_the_spec_layout_has_no_version_marker():
    """UIDAI §3.1 starts at the presence indicator. There is no version field.

    The parser once assumed there was one. So did the test fixture.
    """
    assert UIDAI_FIELD_SEQUENCE[0] == "_presence"
    assert "_version" not in UIDAI_FIELD_SEQUENCE


def test_marker_layout_is_the_spec_layout_plus_one_leading_field():
    """Cards carrying a literal "V2" prefix exist alongside spec-format cards.

    The two layouts must differ by exactly that one field — anything else means
    one of the maps has drifted.
    """
    assert field_map_for("V2") == ("_version", *UIDAI_FIELD_SEQUENCE)


def test_presence_indicator_is_not_mistaken_for_a_version_marker():
    """A real card's field 0 is "0", "1", "2" or "3" — UIDAI §2.2(a).

    Treating one of those as a version marker shifts every field by one.
    """
    for indicator in ("0", "1", "2", "3"):
        assert detect_version(indicator) == "V1"


def test_every_declared_map_is_a_known_version():
    assert set(FIELD_MAPS) == {"V1", "V2"}


# --------------------------------------------------------------------------- #
# The published sample — skips unless fetched locally
# --------------------------------------------------------------------------- #


@pytest.fixture
def spec_sample() -> str:
    if not SPEC_SAMPLE.is_file():
        pytest.skip(f"UIDAI sample not present at {SPEC_SAMPLE} — run scripts/fetch_spec_sample.py")
    return SPEC_SAMPLE.read_text(encoding="utf-8").strip()


def test_uidai_sample_payload_parses(spec_sample: str):
    """★ Ground truth: UIDAI's own published payload, parsed by our parser."""
    payload = SecureQrParser().parse(spec_sample)

    assert payload.version == "V1"
    assert len(payload.signature) == 256
    assert payload.signed_bytes


def test_uidai_sample_fields_land_in_the_right_columns(spec_sample: str):
    """Structural checks only — no value is asserted or printed.

    `pincode` being six digits and `state` being a real Indian state are the
    discriminating checks: if the address order were shifted, they would hold
    a house number and a street name instead.
    """
    import re

    states = {
        "andhra pradesh", "arunachal pradesh", "assam", "bihar", "chhattisgarh", "goa",
        "gujarat", "haryana", "himachal pradesh", "jharkhand", "karnataka", "kerala",
        "madhya pradesh", "maharashtra", "manipur", "meghalaya", "mizoram", "nagaland",
        "odisha", "orissa", "punjab", "rajasthan", "sikkim", "tamil nadu", "telangana",
        "tripura", "uttar pradesh", "uttarakhand", "west bengal", "delhi",
        "jammu and kashmir", "ladakh", "puducherry", "chandigarh",
    }  # fmt: skip

    payload = SecureQrParser().parse(spec_sample)
    identity, address = payload.identity, payload.address

    # UIDAI §3.1: referenceId is the last 4 Aadhaar digits plus a
    # DDMMYYYYHHMMSSsss timestamp — 21 characters.
    assert identity.reference_id[:4].isdigit()
    assert len(identity.reference_id) == 21

    assert re.match(r"^\d{1,4}[-/]\d{1,2}[-/]\d{1,4}$", identity.dob.strip())
    assert identity.gender.strip().upper() in {"M", "F", "T"}

    assert re.match(r"^\d{6}$", (address.pincode or "").strip())
    assert (address.state or "").strip().lower() in states
    assert not (address.district or "").strip().isdigit()

    # UIDAI §2.2: a JPEG2000 photograph sits between the text fields and the
    # hashes. Its presence proves the tail offset was computed correctly.
    assert payload.photo is not None
    assert len(payload.photo) > 100
