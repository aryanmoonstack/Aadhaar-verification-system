"""Contract conformance tests — Step 0.

These tests exist to make architectural drift fail CI. They assert the invariants
written in CONTRACTS.md, so a future step that quietly changes a verdict, adds a
tenth outcome, or introduces auto-rejection breaks the build immediately rather
than surfacing weeks later in production.
"""

from __future__ import annotations

import pytest

from avs.contracts import (
    CONTRACT_VERSION,
    AadhaarIdentity,
    CheckName,
    CheckResult,
    DocType,
    ErrorCode,
    SignatureProof,
    Verdict,
    VerificationResult,
)


class TestVerdictContract:
    """CONTRACTS.md §1."""

    def test_exactly_nine_verdicts(self) -> None:
        assert len(list(Verdict)) == 9, "Adding a verdict is a contract change"

    def test_expected_verdict_names(self) -> None:
        assert {v.value for v in Verdict} == {
            "VERIFIED",
            "TAMPERED",
            "UNREADABLE",
            "LEGACY_FORMAT",
            "WRONG_DOCUMENT",
            "PROFILE_MISMATCH",
            "TEXT_MISMATCH",
            "DUPLICATE",
            "ERROR",
        }

    def test_rule_1_only_verified_auto_approves(self) -> None:
        approving = [v for v in Verdict if v.is_auto_approve]
        assert approving == [Verdict.VERIFIED]

    def test_rule_2_nothing_is_ever_auto_rejected(self) -> None:
        assert all(v.is_auto_reject is False for v in Verdict)

    def test_duplicate_cannot_be_retried(self) -> None:
        assert Verdict.DUPLICATE.allows_retry is False

    @pytest.mark.parametrize(
        "verdict",
        [
            Verdict.TAMPERED,
            Verdict.PROFILE_MISMATCH,
            Verdict.TEXT_MISMATCH,
            Verdict.DUPLICATE,
            Verdict.ERROR,
        ],
    )
    def test_review_bearing_verdicts(self, verdict: Verdict) -> None:
        assert verdict.requires_human_review is True


class TestCheckContract:
    """CONTRACTS.md §2 and §7 — the AI boundary."""

    def test_only_signature_verify_bears_the_verdict(self) -> None:
        bearing = [c for c in CheckName if c.is_verdict_bearing]
        assert bearing == [CheckName.SIGNATURE_VERIFY]

    def test_no_ai_check_is_verdict_bearing(self) -> None:
        """The core architectural law: AI never decides."""
        for check in CheckName:
            if check.is_ai_produced:
                assert check.is_verdict_bearing is False, (
                    f"{check.value} is AI-produced and must never bear the verdict"
                )

    def test_check_results_are_the_frozen_four(self) -> None:
        assert {r.value for r in CheckResult} == {"PASS", "FAIL", "WARN", "SKIP"}


class TestErrorContract:
    """CONTRACTS.md §3."""

    def test_ai_errors_are_never_fatal(self) -> None:
        for code in (ErrorCode.MODEL_LOAD_FAILED, ErrorCode.MODEL_INFERENCE_FAILED):
            assert code.is_ai_degradation is True

    def test_signature_invalid_is_not_retryable(self) -> None:
        """A tampered document does not become genuine on retry."""
        assert ErrorCode.SIGNATURE_INVALID.is_retryable is False


class TestIdentityContract:
    """CONTRACTS.md §4 — the full Aadhaar number must be unrepresentable."""

    def test_no_field_for_full_aadhaar_number(self) -> None:
        fields = set(AadhaarIdentity.model_fields)
        forbidden = {"aadhaar_number", "aadhaar", "uid", "full_aadhaar", "number"}
        assert not (fields & forbidden), "AadhaarIdentity must never carry the full 12-digit number"

    def test_last4_must_be_four_digits(self) -> None:
        with pytest.raises(ValueError):
            AadhaarIdentity(
                name="Test User",
                dob="1995-03-14",
                gender="M",
                aadhaar_last4="12345",
                reference_id="ref",
            )

    def test_last4_rejects_non_digits(self) -> None:
        with pytest.raises(ValueError):
            AadhaarIdentity(
                name="Test User",
                dob="1995-03-14",
                gender="M",
                aadhaar_last4="12a4",
                reference_id="ref",
            )


class TestApprovalSafety:
    """Belt-and-braces: VERIFIED alone must never approve without a valid proof."""

    def test_verified_without_proof_does_not_auto_approve(self) -> None:
        result = VerificationResult(job_id="j1", verdict=Verdict.VERIFIED, proof=None)
        assert result.is_auto_approve is False

    def test_verified_with_invalid_proof_does_not_auto_approve(self) -> None:
        result = VerificationResult(
            job_id="j1",
            verdict=Verdict.VERIFIED,
            proof=SignatureProof(valid=False),
        )
        assert result.is_auto_approve is False

    def test_verified_with_valid_proof_approves(self) -> None:
        result = VerificationResult(
            job_id="j1",
            verdict=Verdict.VERIFIED,
            proof=SignatureProof(valid=True, signed_byte_length=1482),
        )
        assert result.is_auto_approve is True


class TestDocTypeContract:
    def test_aadhaar_variants_recognised(self) -> None:
        assert DocType.AADHAAR_FRONT.is_aadhaar
        assert DocType.AADHAAR_PVC.is_aadhaar
        assert not DocType.OTHER_ID.is_aadhaar
        assert not DocType.UNKNOWN.is_aadhaar


def test_contract_version_is_pinned() -> None:
    assert CONTRACT_VERSION == "1.3.0"
