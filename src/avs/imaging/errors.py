"""Imaging exceptions — Step 4."""

from __future__ import annotations

from avs.contracts import ErrorCode

__all__ = ["ImagingError"]


class ImagingError(Exception):
    """Raised only when the input cannot be decoded at all.

    An individual strategy failing is NOT an error — the generator skips it and
    continues. One broken recipe must not deny the decoder the other twenty.
    """

    def __init__(self, message: str, code: ErrorCode = ErrorCode.CORRUPT_IMAGE) -> None:
        self.code = code
        self.message = message
        super().__init__(f"{code.value}: {message}")
