"""avs.parser — Secure QR payload parsing.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 1
Provides : SecureQrParser.parse(str) -> QrPayload, ParseError
Consumes : avs.contracts
Used by  : avs.crypto (Step 1), avs.ocr (Step 17)
Status   : COMPLETE

⚠ Contains the security invariant from CONTRACTS.md §5:
    signed_bytes = payload[:-256], signature = payload[-256:]
"""

from avs.parser.errors import ParseError
from avs.parser.fields import FIELD_MAPS, SIGNATURE_LENGTH, detect_version
from avs.parser.payload import SecureQrParser

__all__ = [
    "FIELD_MAPS",
    "SIGNATURE_LENGTH",
    "ParseError",
    "SecureQrParser",
    "detect_version",
]
