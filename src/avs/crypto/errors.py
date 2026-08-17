"""Crypto exceptions — Step 1."""

from __future__ import annotations

from avs.contracts import ErrorCode

__all__ = ["CryptoError"]


class CryptoError(Exception):
    """Raised for trust-store problems, never for an invalid signature.

    An invalid signature is a normal, expected outcome — it returns
    SignatureProof(valid=False), not an exception. Exceptions here mean the
    verifier itself could not run.
    """

    def __init__(self, code: ErrorCode, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"{code.value}: {message}")
