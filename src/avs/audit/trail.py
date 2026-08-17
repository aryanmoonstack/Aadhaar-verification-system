"""Hash-chained audit trail — Step 9.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 9
Provides : AuditEntry, AuditSink (Protocol), FileAuditTrail, NullAuditSink, verify_chain()
Consumes : avs.contracts
Used by  : avs.api, avs.pipeline
Status   : COMPLETE

WHY AN AUDIT TRAIL AT ALL
-------------------------
This service decides whether a person's identity document is genuine. When an
employee disputes a rejection, or a regulator asks how a particular approval was
reached, "the logs probably have it" is not an answer. The trail records every
verdict with the evidence that produced it.

⛔ WHY IT IS HASH-CHAINED, NOT JUST APPENDED

   A plain log can be edited. Someone with write access can delete the entry
   showing a document was rejected, or add one showing it was approved, and
   nothing about the file would look wrong.

   Each entry therefore carries the SHA-256 of the entry before it. Altering,
   deleting or reordering any entry breaks every hash after it, and
   ``verify_chain`` says exactly where. This does not PREVENT tampering — an
   attacker with write access can rewrite the whole chain — but it makes silent,
   partial tampering impossible, which is the realistic threat.

   Genuine tamper-proofing needs an append-only store or an external notary.
   The Protocol is here so one can be added without touching callers.

⛔ THE TRAIL CONTAINS NO PERSONAL DATA

   Step 8 established that AVS never persists Aadhaar data. The audit trail is
   the ONE thing it does persist, so the rule matters more here than anywhere
   else: verdicts, timings, certificate serials, and the salted reference HASH.
   Never a name, a date of birth, an address, an image, or any part of an
   Aadhaar number. Enforced by ``tests/unit/test_audit.py``, not by care.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol, runtime_checkable

__all__ = [
    "GENESIS_HASH",
    "AuditEntry",
    "AuditSink",
    "ChainBreak",
    "FileAuditTrail",
    "NullAuditSink",
    "verify_chain",
]

#: The previous-hash of the first entry. A fixed, known value so the start of a
#: chain is unambiguous — an empty string would be indistinguishable from a
#: missing field.
GENESIS_HASH = "0" * 64


@dataclass(frozen=True, slots=True)
class AuditEntry:
    """One verdict, and the evidence for it.

    ⛔ Every field here is written to disk and kept. Adding a field that could
       carry personal data breaks the Step 8 statelessness promise.
    """

    job_id: str
    tenant_id: str
    verdict: str
    at: str
    """ISO-8601 UTC."""

    signature_valid: bool = False
    certificate_serial: str | None = None
    certificate_expired: bool = False
    qr_version: str | None = None

    reference_hash: str | None = None
    """Salted HMAC of the reference id. Identifies a *card* across submissions
    without being reversible to an Aadhaar number."""

    decoded: bool = False
    decoder: str | None = None
    strategy: str | None = None
    variants_tried: int = 0
    processing_ms: int = 0
    error_code: str | None = None

    previous_hash: str = GENESIS_HASH
    entry_hash: str = ""

    def payload(self) -> dict:
        """Everything except the entry's own hash — what gets hashed."""
        data = asdict(self)
        data.pop("entry_hash")
        return data

    def compute_hash(self) -> str:
        """SHA-256 over the canonical JSON of the payload.

        ``sort_keys`` and ``separators`` are load-bearing: without a canonical
        form the same entry could hash two different ways depending on dict
        ordering, and the chain would break for no reason.
        """
        canonical = json.dumps(self.payload(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def sealed(self) -> AuditEntry:
        """This entry with its hash filled in."""
        from dataclasses import replace

        return replace(self, entry_hash=self.compute_hash())


@dataclass(frozen=True, slots=True)
class ChainBreak:
    """Where and how a chain failed verification."""

    line: int
    reason: str
    job_id: str | None = None


@runtime_checkable
class AuditSink(Protocol):
    """Where audit entries go. A Protocol so a SIEM or append-only store can
    replace the file backend without touching the pipeline."""

    def record(self, entry: AuditEntry) -> AuditEntry:
        """Append an entry, returning it sealed with its chain hashes."""
        ...


class NullAuditSink:
    """Discards everything. For tests and for the CLI, which has no trail.

    Deliberately explicit rather than accepting ``None`` everywhere: a caller
    that wants no audit should say so.
    """

    def record(self, entry: AuditEntry) -> AuditEntry:
        return entry.sealed()


class FileAuditTrail:
    """Append-only JSON Lines, one entry per line, chained by hash.

    JSONL rather than a single JSON document so that appending is a single
    write with no read-modify-write, and so a truncated final line damages one
    entry rather than the whole file.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._last_hash: str | None = None

    def record(self, entry: AuditEntry) -> AuditEntry:
        """Seal and append. Thread-safe — workers record concurrently.

        The lock covers reading the previous hash AND writing, because those two
        steps together are what make the chain a chain. Splitting them lets two
        workers read the same previous hash and produce a fork.
        """
        from dataclasses import replace

        with self._lock:
            previous = self._resolve_last_hash()
            sealed = replace(entry, previous_hash=previous).sealed()

            self.path.parent.mkdir(parents=True, exist_ok=True)
            line = json.dumps(asdict(sealed), sort_keys=True, separators=(",", ":"))
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
                handle.flush()

            self._last_hash = sealed.entry_hash
            return sealed

    def _resolve_last_hash(self) -> str:
        """The hash of the final entry, or GENESIS on an empty/absent file.

        Cached after the first call. Read from disk on startup so a restart
        continues the existing chain rather than starting a second one — two
        chains in one file is indistinguishable from tampering.
        """
        if self._last_hash is not None:
            return self._last_hash

        if not self.path.is_file():
            self._last_hash = GENESIS_HASH
            return self._last_hash

        last = GENESIS_HASH
        with self.path.open("r", encoding="utf-8") as handle:
            for raw in handle:
                stripped = raw.strip()
                if not stripped:
                    continue
                try:
                    last = json.loads(stripped).get("entry_hash", last)
                except json.JSONDecodeError:
                    # A damaged line cannot extend the chain. verify_chain
                    # reports it; recording continues from the last good hash.
                    continue

        self._last_hash = last
        return last

    def entries(self) -> list[AuditEntry]:
        """Every entry, in order. For verification and reporting."""
        if not self.path.is_file():
            return []

        found: list[AuditEntry] = []
        with self.path.open("r", encoding="utf-8") as handle:
            for raw in handle:
                stripped = raw.strip()
                if not stripped:
                    continue
                try:
                    found.append(AuditEntry(**json.loads(stripped)))
                except (json.JSONDecodeError, TypeError):
                    continue
        return found


def verify_chain(path: str | Path) -> list[ChainBreak]:
    """Check every link. An empty list means the trail is intact.

    Two independent checks per entry:

    * **Self-consistency** — does the entry hash to the value it claims? Catches
      any edit to the entry's own content.
    * **Linkage** — does its `previous_hash` match the entry before it? Catches
      deletion, insertion and reordering.

    Both are needed. Re-hashing an edited entry defeats the first check alone;
    the second then fails because the following entry still points at the old
    hash.
    """
    trail = Path(path)
    if not trail.is_file():
        return [ChainBreak(0, f"audit trail not found: {trail}")]

    breaks: list[ChainBreak] = []
    expected_previous = GENESIS_HASH

    with trail.open("r", encoding="utf-8") as handle:
        for number, raw in enumerate(handle, start=1):
            stripped = raw.strip()
            if not stripped:
                continue

            try:
                entry = AuditEntry(**json.loads(stripped))
            except (json.JSONDecodeError, TypeError) as exc:
                breaks.append(ChainBreak(number, f"entry is not readable: {exc}"))
                continue

            if entry.entry_hash != entry.compute_hash():
                breaks.append(
                    ChainBreak(number, "entry content was altered after signing", entry.job_id)
                )

            if entry.previous_hash != expected_previous:
                breaks.append(
                    ChainBreak(
                        number,
                        "chain link broken — an entry was inserted, deleted or reordered",
                        entry.job_id,
                    )
                )

            expected_previous = entry.entry_hash

    return breaks


def utc_now() -> str:
    """ISO-8601 UTC, second precision. Consistent across every entry."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
