"""avs.audit — tamper-evident record of every verdict.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 9
Provides : AuditEntry, AuditSink (Protocol), FileAuditTrail, NullAuditSink, verify_chain()
Consumes : avs.contracts
Used by  : avs.api, CLI
Status   : COMPLETE

This service decides whether someone's identity document is genuine. When an
employee disputes a rejection, "the logs probably have it" is not an answer.

Each entry carries the SHA-256 of the entry before it, so altering, deleting or
reordering any entry breaks every hash after it and `verify_chain` says where.

⛔ Step 8 established that AVS never persists Aadhaar data. This trail is the one
   exception, so the rule is tightest here: verdicts, timings, certificate
   serials and a salted reference hash. Never a name, a date of birth, an image,
   or any part of an Aadhaar number.
"""

from avs.audit.trail import (
    GENESIS_HASH,
    AuditEntry,
    AuditSink,
    ChainBreak,
    FileAuditTrail,
    NullAuditSink,
    utc_now,
    verify_chain,
)

__all__ = [
    "GENESIS_HASH",
    "AuditEntry",
    "AuditSink",
    "ChainBreak",
    "FileAuditTrail",
    "NullAuditSink",
    "utc_now",
    "verify_chain",
]
