"""avs.crypto — ★ signature verification. THE VERDICT.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 1
Provides : SecureQrVerifier.verify(QrPayload) -> SignatureProof, CryptoError
Consumes : avs.contracts, avs.parser.fields, avs.truststore, cryptography
Used by  : avs.rules (Step 6)
Status   : COMPLETE

⛔ This is the ONLY module that can produce Verdict.VERIFIED.
   CONTRACTS.md §1 Rule 1 and §7. No avs.ai import may ever appear here —
   tests/unit/test_ai_boundary.py enforces this at the AST level.
"""

from avs.crypto.errors import CryptoError
from avs.crypto.verifier import SecureQrVerifier

__all__ = ["CryptoError", "SecureQrVerifier"]
