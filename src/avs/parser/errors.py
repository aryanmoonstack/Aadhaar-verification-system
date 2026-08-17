"""Parser exceptions — Step 1."""

from __future__ import annotations

from avs.contracts import ErrorCode

__all__ = ["ParseError"]


class ParseError(Exception):
    """Raised when a Secure QR payload cannot be unpacked.

    Always carries an ErrorCode from the parse family so the verdict engine can
    map it deterministically. See CONTRACTS.md §3.
    """

    def __init__(self, code: ErrorCode, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"{code.value}: {message}")

    @property
    def is_legacy(self) -> bool:
        """Pre-2018 unsigned QR — maps to Verdict.LEGACY_FORMAT, not TAMPERED."""
        return self.code is ErrorCode.PAYLOAD_LEGACY_UNSIGNED
