"""Secure QR field maps — declarative, version-dispatched.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 1
Provides : FIELD_MAPS, detect_version()
Consumes : avs.contracts

⚠ VALIDATION STATUS
   These field orders are implemented from UIDAI's published Secure QR
   specification. They have NOT yet been validated against real Aadhaar cards —
   that is the exit criterion for Step 1, performed locally by the project owner.

   The maps are deliberately declarative so that correcting an ordering is a
   one-line data change, not a code change. If a real card decodes with fields
   in the wrong slots, fix the tuple below and re-run the suite.

STRUCTURE OF A SECURE QR PAYLOAD
--------------------------------
    QR text  →  large decimal integer
             →  big-endian byte array
             →  gzip/zlib decompress (if compressed)
             →  text fields, delimited by byte 0xFF
             →  photo (JPEG2000)
             →  [mobile hash, 32 bytes]   (if present bit says so)
             →  [email hash, 32 bytes]    (if present bit says so)
             →  signature, FINAL 256 BYTES

The last 256 bytes are the RSA-2048 signature. Everything before them is the
signed region. See CONTRACTS.md §5 — this is the security invariant.
"""

from __future__ import annotations

__all__ = [
    "DELIMITER",
    "FIELD_MAPS",
    "HASH_LENGTH",
    "SIGNATURE_LENGTH",
    "EmailMobilePresence",
    "detect_version",
    "field_map_for",
]

#: Byte separating text fields in the decompressed payload.
DELIMITER = 0xFF

#: RSA-2048 signature length. CONTRACTS.md §5 — do not change casually.
SIGNATURE_LENGTH = 256

#: SHA-256 hash length, for the optional mobile/email hashes.
HASH_LENGTH = 32


class EmailMobilePresence:
    """Meaning of the presence indicator field.

    Per the UIDAI specification, this single digit tells the parser how many
    32-byte hashes follow the photograph.
    """

    NEITHER = "0"
    EMAIL_ONLY = "1"
    MOBILE_ONLY = "2"
    BOTH = "3"

    @staticmethod
    def hash_count(indicator: str) -> int:
        return {"0": 0, "1": 1, "2": 1, "3": 2}.get(indicator, 0)

    @staticmethod
    def has_email(indicator: str) -> bool:
        return indicator in {"1", "3"}

    @staticmethod
    def has_mobile(indicator: str) -> bool:
        return indicator in {"2", "3"}


#: Canonical field names, in payload order, per QR format version.
#:
#: The names map onto CONTRACTS.md §4 canonical fields. ``_presence`` and
#: ``_version`` are internal markers, not emitted in the parsed output.
FIELD_MAPS: dict[str, tuple[str, ...]] = {
    # Post-2018 Secure QR carrying an explicit "V2" version marker.
    "V2": (
        "_version",
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
    ),
    # Secure QR without a version marker — the presence indicator comes first
    # and every subsequent field shifts down by one slot.
    "V1": (
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
    ),
}

#: Version markers that may appear as the first field.
_KNOWN_VERSION_MARKERS = frozenset({"V2", "V3", "V4"})

#: Fields that belong to AadhaarAddress rather than AadhaarIdentity.
ADDRESS_FIELDS = frozenset(
    {
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
    }
)


def detect_version(first_field: str) -> str:
    """Determine the format version from the first decoded text field.

    A leading token like ``V2`` marks the newer format. Anything else means the
    payload begins directly with the presence indicator (the older layout).
    """
    token = first_field.strip().upper()
    if token in _KNOWN_VERSION_MARKERS:
        # V2, V3 and V4 share one field ordering. If a future revision proves
        # otherwise, add its own entry to FIELD_MAPS and branch here.
        return "V2"
    return "V1"


def field_map_for(version: str) -> tuple[str, ...]:
    """Field ordering for a version. Raises KeyError for unknown versions."""
    return FIELD_MAPS[version]
