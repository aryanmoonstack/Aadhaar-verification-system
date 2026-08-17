"""PII redaction tests — Step 0. CONTRACTS.md §10.

If any of these fail, Aadhaar data is reaching the logs. Treat as a build-stopper.
"""

from __future__ import annotations

import pytest

from avs.logging.redaction import (
    AADHAAR_MASK,
    VALUE_MASK,
    RedactingProcessor,
    redact,
    redact_mapping,
)

# Structurally valid but entirely fictional 12-digit strings, used only to prove
# the redactor fires. No real Aadhaar number appears anywhere in this repository.
FAKE_12_DIGIT = [
    "123456789012",
    "1234 5678 9012",
    "1234-5678-9012",
]


class TestPatternRedaction:
    @pytest.mark.parametrize("value", FAKE_12_DIGIT)
    def test_twelve_digit_sequences_are_masked(self, value: str) -> None:
        out = redact(f"user submitted {value} today")
        assert value not in out
        assert AADHAAR_MASK in out

    def test_four_digit_last4_is_preserved(self) -> None:
        """last4 is safe to log and must survive redaction."""
        out = redact("aadhaar_last4=1234")
        assert "1234" in out

    def test_long_digit_runs_are_masked(self) -> None:
        out = redact("ref 9876543210987654")
        assert "9876543210987654" not in out

    def test_large_base64_blobs_are_masked(self) -> None:
        blob = "A" * 300
        assert blob not in redact(f"payload={blob}")

    def test_blob_redaction_fires_before_truncation(self) -> None:
        """A single long token is treated as a blob, which is the stronger control."""
        out = redact("x" * 5000)
        assert len(out) < 5000
        assert "BLOB-REDACTED" in out

    def test_oversized_prose_is_truncated(self) -> None:
        """Text that is not blob-like still gets length-capped."""
        out = redact("word " * 1000)  # 5000 chars, spaced so it is not one token
        assert len(out) < 5000
        assert "truncated" in out

    def test_empty_string_is_safe(self) -> None:
        assert redact("") == ""


class TestMappingRedaction:
    def test_sensitive_keys_are_masked_by_name(self) -> None:
        out = redact_mapping({"raw_payload": "anything at all", "job_id": "j1"})
        assert out["raw_payload"] == VALUE_MASK
        assert out["job_id"] == "j1"

    def test_key_matching_is_case_insensitive(self) -> None:
        out = redact_mapping({"Authorization": "Bearer abc", "TOKEN": "xyz"})
        assert out["Authorization"] == VALUE_MASK
        assert out["TOKEN"] == VALUE_MASK

    def test_bytes_are_never_rendered(self) -> None:
        out = redact_mapping({"blob": b"\x00\x01\x02\x03"})
        assert out["blob"] == "[bytes:4]"

    def test_nested_dicts_are_redacted(self) -> None:
        out = redact_mapping({"outer": {"signature": "sig", "ok": "fine"}})
        assert out["outer"]["signature"] == VALUE_MASK
        assert out["outer"]["ok"] == "fine"

    def test_lists_are_redacted(self) -> None:
        out = redact_mapping({"items": ["id 123456789012", {"photo": "x"}]})
        assert AADHAAR_MASK in out["items"][0]
        assert out["items"][1]["photo"] == VALUE_MASK

    def test_safe_fields_pass_through(self) -> None:
        payload = {
            "job_id": "abc-123",
            "tenant_id": "t-1",
            "verdict": "VERIFIED",
            "processing_ms": 1840,
        }
        assert redact_mapping(payload) == payload


class TestProcessor:
    def test_processor_redacts_event_dict(self) -> None:
        processor = RedactingProcessor()
        out = processor(None, "info", {"event": "parsed", "raw_payload": "secret"})
        assert out["raw_payload"] == VALUE_MASK
        assert out["event"] == "parsed"

    def test_careless_call_site_is_still_protected(self) -> None:
        """The whole point: a developer logging a payload directly is still safe."""
        processor = RedactingProcessor()
        out = processor(None, "info", {"event": "debug", "msg": "uid 123456789012"})
        assert "123456789012" not in out["msg"]
