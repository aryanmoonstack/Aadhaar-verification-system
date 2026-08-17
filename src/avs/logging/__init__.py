"""avs.logging — structured logging with mandatory PII redaction.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 0
Provides : configure_logging(), get_logger(), redact()
Consumes : nothing
Status   : COMPLETE

CONTRACTS.md §10 — redaction is applied in the processor chain, so it cannot be
bypassed by a careless call site.
"""

from avs.logging.redaction import RedactingProcessor, redact, redact_mapping
from avs.logging.setup import configure_logging, get_logger

__all__ = [
    "RedactingProcessor",
    "configure_logging",
    "get_logger",
    "redact",
    "redact_mapping",
]
