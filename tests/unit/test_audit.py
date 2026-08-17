"""Audit trail — Step 9.

⛔ TWO PROMISES ARE ENFORCED HERE

   **Tamper-evidence.** Someone with write access must not be able to quietly
   flip a rejection into an approval, or delete the record of one. They can
   rewrite the whole chain — nothing short of an append-only store prevents
   that — but they cannot make a *partial* edit that goes unnoticed, which is
   the realistic threat.

   **No personal data.** Step 8 established that AVS never persists Aadhaar
   data. This trail is the single exception to that, so it is the one place the
   rule could quietly erode. Asserted, not trusted.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from avs.audit import (
    GENESIS_HASH,
    AuditEntry,
    FileAuditTrail,
    NullAuditSink,
    utc_now,
    verify_chain,
)


def entry(job: str, verdict: str = "VERIFIED", **kwargs) -> AuditEntry:
    return AuditEntry(job_id=job, tenant_id="m-one", verdict=verdict, at=utc_now(), **kwargs)


@pytest.fixture
def trail(tmp_path: Path) -> FileAuditTrail:
    return FileAuditTrail(tmp_path / "audit.jsonl")


def rewrite(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------- #
# The chain
# --------------------------------------------------------------------------- #


def test_an_untouched_trail_verifies(trail: FileAuditTrail):
    for index in range(5):
        trail.record(entry(f"job-{index}"))

    assert verify_chain(trail.path) == []


def test_the_first_entry_starts_from_genesis(trail: FileAuditTrail):
    """An unambiguous start. An empty previous_hash would be indistinguishable
    from a missing field, and from a chain whose head was deleted."""
    sealed = trail.record(entry("first"))
    assert sealed.previous_hash == GENESIS_HASH


def test_each_entry_links_to_the_one_before(trail: FileAuditTrail):
    first = trail.record(entry("a"))
    second = trail.record(entry("b"))
    assert second.previous_hash == first.entry_hash


# --------------------------------------------------------------------------- #
# ★ Tampering
# --------------------------------------------------------------------------- #


def test_flipping_a_rejection_into_an_approval_is_detected(trail: FileAuditTrail):
    """★ The attack this whole module exists to catch."""
    trail.record(entry("clean-1"))
    trail.record(entry("disputed", verdict="TAMPERED"))
    trail.record(entry("clean-2"))

    lines = trail.path.read_text(encoding="utf-8").splitlines()
    forged = json.loads(lines[1])
    forged["verdict"] = "VERIFIED"
    lines[1] = json.dumps(forged, sort_keys=True, separators=(",", ":"))
    rewrite(trail.path, lines)

    breaks = verify_chain(trail.path)
    assert breaks, "an altered verdict went undetected"
    assert breaks[0].line == 2
    assert "altered" in breaks[0].reason


def test_deleting_an_entry_is_detected(trail: FileAuditTrail):
    """★ Harder than editing, because nothing that remains is itself wrong.

    Only the LINKAGE reveals it — the entry after the hole still points at a
    hash that is no longer present.
    """
    for index in range(4):
        trail.record(entry(f"job-{index}"))

    lines = trail.path.read_text(encoding="utf-8").splitlines()
    rewrite(trail.path, [lines[0], *lines[2:]])  # remove entry 2

    breaks = verify_chain(trail.path)
    assert breaks, "a deleted entry went undetected"
    assert any("chain link broken" in b.reason for b in breaks)


def test_reordering_entries_is_detected(trail: FileAuditTrail):
    for index in range(4):
        trail.record(entry(f"job-{index}"))

    lines = trail.path.read_text(encoding="utf-8").splitlines()
    rewrite(trail.path, [lines[0], lines[2], lines[1], lines[3]])

    assert verify_chain(trail.path), "reordering went undetected"


def test_inserting_a_forged_entry_is_detected(trail: FileAuditTrail):
    """An attacker adds an approval that never happened. Even if they hash it
    correctly, it does not link to what follows."""
    trail.record(entry("real-1"))
    trail.record(entry("real-2"))

    lines = trail.path.read_text(encoding="utf-8").splitlines()
    forged = entry("never-happened").sealed()
    from dataclasses import asdict

    lines.insert(1, json.dumps(asdict(forged), sort_keys=True, separators=(",", ":")))
    rewrite(trail.path, lines)

    assert verify_chain(trail.path), "an inserted entry went undetected"


def test_a_rehashed_edit_is_still_caught_by_the_linkage(trail: FileAuditTrail):
    """⛔ The reason BOTH checks exist.

    A careful attacker edits an entry *and* recomputes its hash, defeating the
    self-consistency check. The entry after it still carries the old hash, so
    the linkage check fires.
    """
    trail.record(entry("a"))
    trail.record(entry("disputed", verdict="TAMPERED"))
    trail.record(entry("c"))

    lines = trail.path.read_text(encoding="utf-8").splitlines()
    forged = json.loads(lines[1])
    forged["verdict"] = "VERIFIED"
    rebuilt = AuditEntry(**{k: v for k, v in forged.items() if k != "entry_hash"}).sealed()
    from dataclasses import asdict

    lines[1] = json.dumps(asdict(rebuilt), sort_keys=True, separators=(",", ":"))
    rewrite(trail.path, lines)

    breaks = verify_chain(trail.path)
    assert breaks, "a re-hashed edit defeated both checks"
    assert any("chain link broken" in b.reason for b in breaks)


def test_a_missing_trail_is_reported_not_silently_passed(tmp_path: Path):
    """⚠ An absent file must never look like a clean chain."""
    breaks = verify_chain(tmp_path / "never-created.jsonl")
    assert breaks and "not found" in breaks[0].reason


# --------------------------------------------------------------------------- #
# ⛔ No personal data
# --------------------------------------------------------------------------- #


def test_the_entry_has_no_field_that_could_hold_personal_data():
    """Adding `name` or `dob` here would break the Step 8 promise silently."""
    forbidden = {
        "name", "dob", "gender", "address", "care_of", "house", "street",
        "landmark", "location", "vtc", "sub_district", "district", "state",
        "pincode", "post_office", "photo", "aadhaar", "aadhaar_last4",
        "reference_id", "mobile", "email",
    }  # fmt: skip
    fields = set(AuditEntry.__dataclass_fields__)

    assert not (fields & forbidden), (
        f"personal-data fields on the audit entry: {fields & forbidden}"
    )


def test_a_written_trail_contains_no_aadhaar_number(trail: FileAuditTrail):
    import re

    trail.record(entry("job-1", reference_hash="hmac-sha256:" + "a" * 64))
    text = trail.path.read_text(encoding="utf-8")

    assert not re.search(r"\b\d{12}\b", text)


def test_the_reference_hash_is_a_hash_not_an_identifier(trail: FileAuditTrail):
    """It links submissions of the same card without being reversible."""
    sealed = trail.record(entry("job-1", reference_hash="hmac-sha256:" + "b" * 64))
    assert sealed.reference_hash.startswith("hmac-sha256:")


# --------------------------------------------------------------------------- #
# Operational behaviour
# --------------------------------------------------------------------------- #


def test_a_restart_continues_the_existing_chain(tmp_path: Path):
    """⛔ Two chains in one file are indistinguishable from tampering.

    A fresh process must read the last hash from disk rather than starting again
    from genesis.
    """
    path = tmp_path / "audit.jsonl"
    first = FileAuditTrail(path)
    first.record(entry("before-restart"))

    restarted = FileAuditTrail(path)  # a new process
    restarted.record(entry("after-restart"))

    assert verify_chain(path) == [], "the restart forked the chain"


def test_concurrent_writers_produce_one_unbroken_chain(tmp_path: Path):
    """Workers record concurrently. Reading the previous hash and appending must
    be atomic together, or two threads fork the chain from the same parent."""
    import threading

    trail = FileAuditTrail(tmp_path / "audit.jsonl")
    barrier = threading.Barrier(8)

    def record(index: int) -> None:
        barrier.wait()
        trail.record(entry(f"job-{index}"))

    threads = [threading.Thread(target=record, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(trail.entries()) == 8
    assert verify_chain(trail.path) == [], "concurrent writers forked the chain"


def test_the_null_sink_seals_without_writing(tmp_path: Path):
    sealed = NullAuditSink().record(entry("job-1"))
    assert sealed.entry_hash
    assert not list(tmp_path.iterdir())
