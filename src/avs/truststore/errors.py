"""Trust store exceptions — Step 2."""

from __future__ import annotations

from avs.contracts import ErrorCode

__all__ = ["TrustStoreError"]


class TrustStoreError(Exception):
    """Raised only when the service is unsafe to start.

    Individual unreadable certificate files are recorded as ``LoadIssue`` and do
    not raise — one bad file should not take down a store that still holds
    working certificates. This exception is reserved for conditions where
    continuing would be worse than failing:

    * the certificate directory does not exist
    * pinning is required but no FINGERPRINTS.txt is present
    """

    def __init__(self, message: str, code: ErrorCode = ErrorCode.CERTIFICATE_LOAD_FAILED) -> None:
        self.code = code
        self.message = message
        super().__init__(message)
