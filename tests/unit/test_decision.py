"""The front-end decision projection — CONTRACTS.md §1.

`DecisionStatus` collapses nine verdicts into the three things an upload screen
can do. Collapsing is lossy by design, so these tests exist to prove the loss is
the intended one — and that the two absolute rules survive the projection:

  Rule 1  APPROVED requires a valid signature, not just the VERIFIED label.
  Rule 2  Nothing is ever auto-rejected. There is no REJECTED status to reach.
"""

from __future__ import annotations

import pytest

from avs.api.app import _decision_for
from avs.contracts import (
    DecisionStatus,
    SignatureProof,
    VerificationResult,
    Verdict,
)


def _result(verdict: Verdict, *, signature_valid: bool | None = None) -> VerificationResult:
    """A settled result carrying `verdict`, with a proof only when asked for."""
    proof = None
    if signature_valid is not None:
        proof = SignatureProof(valid=signature_valid)
    return VerificationResult(
        job_id="test-job",
        verdict=verdict,
        proof=proof,
        user_message="placeholder message",
    )


# --------------------------------------------------------------------------- #
# Rule 2 — nothing is ever auto-rejected
# --------------------------------------------------------------------------- #


class TestNothingIsEverRejected:
    def test_there_is_no_rejected_status_at_all(self) -> None:
        """⛔ The strongest form of the guarantee: the value does not exist.

        A mapping bug can send a verdict to the wrong status. It cannot send one
        to a status that was never defined.
        """
        assert {s.value for s in DecisionStatus} == {"APPROVED", "RETRY", "REVIEW"}
        assert not any("REJECT" in s.value for s in DecisionStatus)

    @pytest.mark.parametrize("verdict", list(Verdict))
    def test_every_verdict_maps_to_something_actionable(self, verdict: Verdict) -> None:
        """All nine, exhaustively — `list(Verdict)` grows if a tenth is ever added."""
        status = verdict.decision_status
        assert status in set(DecisionStatus)
        assert verdict.is_auto_reject is False

    @pytest.mark.parametrize("verdict", list(Verdict))
    def test_no_message_ever_accuses_anyone(self, verdict: Verdict) -> None:
        """CONTRACTS.md §1 language rule, checked at the boundary it leaves by."""
        from avs.rules import MESSAGES

        message = MESSAGES[verdict].lower()
        assert "fake" not in message
        assert "fraud" not in message
        assert "forged" not in message


# --------------------------------------------------------------------------- #
# Rule 1 — APPROVED requires a signature
# --------------------------------------------------------------------------- #


class TestApprovalRequiresASignature:
    def test_verified_with_a_valid_proof_is_approved(self) -> None:
        decision = _decision_for(_result(Verdict.VERIFIED, signature_valid=True))
        assert decision is not None
        assert decision.status is DecisionStatus.APPROVED
        assert decision.status_code == 200
        assert decision.signature_valid is True
        assert decision.needs_review is False

    @pytest.mark.parametrize("proof", [None, False])
    def test_verified_without_a_valid_proof_is_downgraded(self, proof) -> None:
        """⛔ The single most important test in this file.

        A VERIFIED verdict with no signature behind it should be impossible —
        the rules engine cannot produce one today. This asserts what happens if
        a future change makes it possible anyway: it becomes REVIEW, so a human
        sees an anomaly, rather than APPROVED, which would hand a client a
        forged document wearing an approval.

        Failing loudly beats trusting an upstream invariant that a refactor can
        quietly break.
        """
        kwargs = {} if proof is None else {"signature_valid": proof}
        decision = _decision_for(_result(Verdict.VERIFIED, **kwargs))

        assert decision is not None
        assert decision.status is DecisionStatus.REVIEW
        assert decision.status is not DecisionStatus.APPROVED
        assert decision.signature_valid is False
        assert decision.needs_review is True
        # The verdict itself is reported unchanged — the projection may downgrade
        # the advice, never rewrite the finding.
        assert decision.verdict == "VERIFIED"

    @pytest.mark.parametrize("verdict", [v for v in Verdict if v is not Verdict.VERIFIED])
    def test_no_other_verdict_can_reach_approved(self, verdict: Verdict) -> None:
        """Even handed a valid proof, which several legitimately carry."""
        decision = _decision_for(_result(verdict, signature_valid=True))
        assert decision is not None
        assert decision.status is not DecisionStatus.APPROVED
        assert decision.status_code != 200


# --------------------------------------------------------------------------- #
# The mapping itself
# --------------------------------------------------------------------------- #


class TestTheMapping:
    @pytest.mark.parametrize(
        ("verdict", "expected"),
        [
            (Verdict.VERIFIED, DecisionStatus.APPROVED),
            # Fixed by sending a better or different file.
            (Verdict.UNREADABLE, DecisionStatus.RETRY),
            (Verdict.LEGACY_FORMAT, DecisionStatus.RETRY),
            (Verdict.WRONG_DOCUMENT, DecisionStatus.RETRY),
            # ⚠ TAMPERED is RETRY, not REVIEW. §1 marks it BOTH review-worthy and
            #   retry-allowed, and its message already reads "please upload clear
            #   photos of your original card". The employee's only useful action
            #   is to re-upload; HR is alerted separately via needs_review.
            (Verdict.TAMPERED, DecisionStatus.RETRY),
            # Our fault. Retrying is honest advice and must not read as a problem
            # with their document.
            (Verdict.ERROR, DecisionStatus.RETRY),
            # A better photograph cannot change any of these three.
            (Verdict.PROFILE_MISMATCH, DecisionStatus.REVIEW),
            (Verdict.TEXT_MISMATCH, DecisionStatus.REVIEW),
            (Verdict.DUPLICATE, DecisionStatus.REVIEW),
        ],
    )
    def test_each_verdict_maps_as_documented(
        self, verdict: Verdict, expected: DecisionStatus
    ) -> None:
        assert verdict.decision_status is expected

    def test_the_mapping_covers_every_verdict(self) -> None:
        """⚠ Guards the parametrize list above from drifting out of date.

        A tenth verdict would otherwise be mapped by the `return RETRY` fallback
        and never noticed.
        """
        covered = {
            Verdict.VERIFIED,
            Verdict.UNREADABLE,
            Verdict.LEGACY_FORMAT,
            Verdict.WRONG_DOCUMENT,
            Verdict.TAMPERED,
            Verdict.ERROR,
            Verdict.PROFILE_MISMATCH,
            Verdict.TEXT_MISMATCH,
            Verdict.DUPLICATE,
        }
        assert covered == set(Verdict)

    def test_tampered_tells_the_employee_to_retry_and_still_alerts_hr(self) -> None:
        """★ The case a single three-way status could not express.

        Two different audiences, two different answers, carried side by side.
        """
        decision = _decision_for(_result(Verdict.TAMPERED, signature_valid=False))
        assert decision is not None
        assert decision.status is DecisionStatus.RETRY
        assert decision.needs_review is True

    def test_status_codes_are_body_codes_not_http_codes(self) -> None:
        assert DecisionStatus.APPROVED.http_status == 200
        assert DecisionStatus.RETRY.http_status == 422
        assert DecisionStatus.REVIEW.http_status == 202

    def test_a_pending_job_has_no_decision(self) -> None:
        """Null until settled. A decision on an unfinished job would be a guess."""
        assert _decision_for(None) is None

    @pytest.mark.parametrize("verdict", list(Verdict))
    def test_the_message_is_passed_through_untouched(self, verdict: Verdict) -> None:
        """⛔ The projection never rewrites wording. It is carefully worded."""
        result = _result(verdict, signature_valid=True)
        decision = _decision_for(result)
        assert decision is not None
        assert decision.message == result.user_message
