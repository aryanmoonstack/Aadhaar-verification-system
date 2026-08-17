"""Ingest exceptions — Step 3."""

from __future__ import annotations

from avs.contracts import ErrorCode

__all__ = ["IngestError"]


class IngestError(Exception):
    """Raised when an upload is rejected at the security boundary.

    Carries two messages deliberately:

    * ``message`` — technical detail for logs and operators
    * ``user_message`` — what the employee is shown

    They differ on purpose. "magic bytes indicate PDF" belongs in a log; the
    employee should read "PDF files are not supported, please upload a photo".
    Never surface the technical message in the UI.
    """

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        user_message: str = "",
    ) -> None:
        self.code = code
        self.message = message
        self.user_message = user_message or "This file could not be processed."
        super().__init__(f"{code.value}: {message}")
