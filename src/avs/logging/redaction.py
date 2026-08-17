"""PII redaction — applied at the log formatter level so it cannot be bypassed.

ARCHITECTURAL CONTRACT — see CONTRACTS.md section 10
----------------------------------------------------
Built in : Step 0
Provides : redact(), RedactingProcessor
Consumes : nothing

This exists from line one of the project, before any Aadhaar data can be handled,
because retrofitting redaction after logs are already leaking is how breaches happen.

Redaction is applied by the structlog processor chain, not by individual call sites.
A developer who carelessly writes ``log.info("payload", raw=qr_string)`` still gets
redacted output. That is the point.
"""

from __future__ import annotations

import re
from typing import Any

__all__ = ["SENSITIVE_KEYS", "RedactingProcessor", "redact", "redact_mapping"]


# 12 consecutive digits, optionally spaced or hyphenated in groups of four.
# Deliberately broad: a false positive costs a redacted log line, a false negative
# costs an Aadhaar number in plaintext.
_AADHAAR_PATTERN = re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b")

# Long digit runs that could be a reference ID or an unformatted Aadhaar number.
_LONG_DIGIT_RUN = re.compile(r"\b\d{12,}\b")

# Base64-ish blobs long enough to be image or payload data.
_BLOB_PATTERN = re.compile(r"\b[A-Za-z0-9+/]{200,}={0,2}\b")

AADHAAR_MASK = "[AADHAAR-REDACTED]"
BLOB_MASK = "[BLOB-REDACTED]"
VALUE_MASK = "[REDACTED]"

#: Keys whose values are never logged, regardless of content.
SENSITIVE_KEYS: frozenset[str] = frozenset(
    {
        "data",
        "raw_payload",
        "payload",
        "qr_string",
        "signed_bytes",
        "signature",
        "photo",
        "image",
        "image_bytes",
        "reference_id",
        "aadhaar",
        "aadhaar_number",
        "password",
        "secret",
        "token",
        "authorization",
        "api_key",
        "hmac",
    }
)

_MAX_STRING_LEN = 2000


def redact(value: str) -> str:
    """Redact Aadhaar-like patterns and oversized blobs from a string."""
    if not value:
        return value

    out = _AADHAAR_PATTERN.sub(AADHAAR_MASK, value)
    out = _LONG_DIGIT_RUN.sub(AADHAAR_MASK, out)
    out = _BLOB_PATTERN.sub(BLOB_MASK, out)

    if len(out) > _MAX_STRING_LEN:
        out = out[:_MAX_STRING_LEN] + f"…[truncated {len(out) - _MAX_STRING_LEN} chars]"
    return out


def redact_mapping(data: dict[str, Any]) -> dict[str, Any]:
    """Recursively redact a mapping: sensitive keys by name, strings by pattern."""
    result: dict[str, Any] = {}
    for key, value in data.items():
        lowered = key.lower()

        if lowered in SENSITIVE_KEYS:
            result[key] = VALUE_MASK
        elif isinstance(value, bytes):
            result[key] = f"[bytes:{len(value)}]"
        elif isinstance(value, str):
            result[key] = redact(value)
        elif isinstance(value, dict):
            result[key] = redact_mapping(value)
        elif isinstance(value, (list, tuple)):
            result[key] = [
                redact_mapping(v)
                if isinstance(v, dict)
                else redact(v)
                if isinstance(v, str)
                else f"[bytes:{len(v)}]"
                if isinstance(v, bytes)
                else v
                for v in value
            ]
        else:
            result[key] = value
    return result


class RedactingProcessor:
    """structlog processor. Placed last in the chain so nothing escapes it."""

    def __call__(
        self,
        logger: Any,
        method_name: str,
        event_dict: dict[str, Any],
    ) -> dict[str, Any]:
        return redact_mapping(event_dict)
