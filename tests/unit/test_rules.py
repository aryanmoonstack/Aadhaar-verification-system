"""Verdict engine and privacy tests — Step 6.

This is where the two absolute rules become executable. If any test in
``TestAbsoluteRules`` fails, the system can approve something it should not, or
accuse someone it should not. Treat either as a build-stopper.
"""

from __future__ import annotations

import pytest

from avs.contracts import (
    AadhaarAddress,
    AadhaarIdentity,
    CheckName,
    CheckOutcome,
    CheckResult,
    ErrorCode,
    SignatureProof,
    Strictness,
    Verdict,
    VerificationResult,
)
from avs.privacy import REDACTED, DataMinimisingFilter
from avs.rules import MESSAGES, DeterministicVerdictEngine, message_for

SECRET = "unit-test-secret-not-a-real-key"


def check(name: CheckName, result: CheckResult, **kwargs) -> CheckOutcome:
    return CheckOutcome(name=name, result=result, **kwargs)


def valid_proof() -> SignatureProof:
    return SignatureProof(valid=True, certificate_serial="abc123", signed_byte_length=1482)


def invalid_proof(error: ErrorCode = ErrorCode.SIGNATURE_INVALID) -> SignatureProof:
    return SignatureProof(valid=False, error=error)


@pytest.fixture
def engine() -> DeterministicVerdictEngine:
    return DeterministicVerdictEngine()


@pytest.fixture
def strict() -> DeterministicVerdictEngine:
    return DeterministicVerdictEngine(strictness=Strictness.STRICT)


@pytest.fixture
def privacy() -> DataMinimisingFilter:
    return DataMinimisingFilter(hash_secret=SECRET)


# --------------------------------------------------------------------------- #
# ★ The two absolute rules
# --------------------------------------------------------------------------- #


class TestAbsoluteRules:
    def test_verified_requires_a_valid_signature(self, engine) -> None:
        """★ Rule 1. Nothing but a valid signature can approve."""
        every_check_passing = [
            check(name, CheckResult.PASS)
            for name in CheckName
            if name != CheckName.SIGNATURE_VERIFY
        ]
        result = engine.decide(every_check_passing, invalid_proof())
        assert result.verdict is not Verdict.VERIFIED

    def test_no_proof_at_all_never_approves(self, engine) -> None:
        passing = [check(name, CheckResult.PASS) for name in CheckName]
        assert engine.decide(passing, None).verdict is not Verdict.VERIFIED

    def test_valid_signature_with_clean_checks_approves(self, engine) -> None:
        result = engine.decide([check(CheckName.SIGNATURE_VERIFY, CheckResult.PASS)], valid_proof())
        assert result.verdict is Verdict.VERIFIED
        assert result.is_auto_approve is True

    @pytest.mark.parametrize("verdict", list(Verdict))
    def test_nothing_is_ever_auto_rejected(self, verdict: Verdict) -> None:
        """★ Rule 2. Every outcome is approve, retry, or human — never reject."""
        assert verdict.is_auto_reject is False

    def test_only_verified_can_auto_approve(self, engine) -> None:
        approving = [v for v in Verdict if v.is_auto_approve]
        assert approving == [Verdict.VERIFIED]


# --------------------------------------------------------------------------- #
# ★ The distinction that matters most
# --------------------------------------------------------------------------- #


class TestOurFaultVersusTheirs:
    """A misconfigured service must never accuse an employee of forgery."""

    def test_signature_mismatch_is_tampered(self, engine) -> None:
        """The document really was altered."""
        result = engine.decide(
            [
                check(
                    CheckName.SIGNATURE_VERIFY, CheckResult.FAIL, error=ErrorCode.SIGNATURE_INVALID
                )
            ],
            invalid_proof(ErrorCode.SIGNATURE_INVALID),
        )
        assert result.verdict is Verdict.TAMPERED

    @pytest.mark.parametrize(
        "fault",
        [
            ErrorCode.TRUSTSTORE_EMPTY,
            ErrorCode.CERTIFICATE_EXPIRED,
            ErrorCode.CERTIFICATE_LOAD_FAILED,
        ],
    )
    def test_service_misconfiguration_is_error_not_tampered(self, engine, fault) -> None:
        """★ An empty trust store means WE are broken, not that the card is fake.

        Both produce ``valid is False``. Conflating them would report a genuine
        Aadhaar as tampered because someone forgot to deploy a certificate.
        """
        result = engine.decide(
            [check(CheckName.SIGNATURE_VERIFY, CheckResult.FAIL, error=fault)],
            invalid_proof(fault),
        )
        assert result.verdict is Verdict.ERROR
        assert result.verdict is not Verdict.TAMPERED

    def test_error_message_does_not_blame_the_employee(self, engine) -> None:
        result = engine.decide([], invalid_proof(ErrorCode.TRUSTSTORE_EMPTY))
        message = result.user_message.lower()
        assert "try again" in message
        for accusation in ("fake", "forg", "fraud", "invalid document", "tamper"):
            assert accusation not in message


# --------------------------------------------------------------------------- #
# Decision table
# --------------------------------------------------------------------------- #


class TestDecisionTable:
    def test_legacy_qr_is_named_not_blamed(self, engine) -> None:
        """A genuine pre-2018 card is not a forgery."""
        result = engine.decide(
            [
                check(
                    CheckName.PAYLOAD_PARSED,
                    CheckResult.FAIL,
                    error=ErrorCode.PAYLOAD_LEGACY_UNSIGNED,
                )
            ],
            None,
        )
        assert result.verdict is Verdict.LEGACY_FORMAT
        assert "older Aadhaar" in result.user_message

    def test_no_qr_found_is_unreadable(self, engine) -> None:
        result = engine.decide(
            [check(CheckName.QR_DECODED, CheckResult.FAIL, error=ErrorCode.QR_NOT_FOUND)],
            None,
        )
        assert result.verdict is Verdict.UNREADABLE

    def test_foreign_qr_only_is_wrong_document(self, engine) -> None:
        """A URL sticker is not an Aadhaar — say so, don't say 'unreadable'."""
        result = engine.decide(
            [
                check(
                    CheckName.QR_DECODED,
                    CheckResult.FAIL,
                    error=ErrorCode.QR_NOT_FOUND,
                    detail="foreign QR only; no QR on: front, back",
                )
            ],
            None,
        )
        assert result.verdict is Verdict.WRONG_DOCUMENT

    def test_wrong_document_type(self, engine) -> None:
        result = engine.decide([check(CheckName.DOCUMENT_TYPE, CheckResult.FAIL)], None)
        assert result.verdict is Verdict.WRONG_DOCUMENT

    def test_ingest_failure_is_unreadable_not_error(self, engine) -> None:
        """★ ERROR means WE are broken and the employee should wait.

        A rejected upload is neither — it is a retry with a different image.
        Reporting it as ERROR tells someone to wait for a fix that is never
        coming.
        """
        result = engine.decide(
            [check(CheckName.FILE_VALIDATION, CheckResult.FAIL, error=ErrorCode.CORRUPT_IMAGE)],
            None,
        )
        assert result.verdict is Verdict.UNREADABLE
        assert "could not open your photos" in result.user_message.lower()

    def test_no_evidence_at_all_is_error(self, engine) -> None:
        assert engine.decide([], None).verdict is Verdict.ERROR


class TestReviewRouting:
    """A valid signature plus a failing advisory check goes to a human."""

    @pytest.mark.parametrize(
        ("failing", "expected"),
        [
            (CheckName.DUPLICATE_CHECK, Verdict.DUPLICATE),
            (CheckName.SIDE_AGREEMENT, Verdict.TEXT_MISMATCH),
            (CheckName.OCR_CROSS_CHECK, Verdict.TEXT_MISMATCH),
            (CheckName.PROFILE_NAME_MATCH, Verdict.PROFILE_MISMATCH),
            (CheckName.PROFILE_DOB_MATCH, Verdict.PROFILE_MISMATCH),
        ],
    )
    def test_advisory_failure_routes_to_review(self, engine, failing, expected) -> None:
        result = engine.decide(
            [
                check(CheckName.SIGNATURE_VERIFY, CheckResult.PASS),
                check(failing, CheckResult.FAIL),
            ],
            valid_proof(),
        )
        assert result.verdict is expected
        assert result.verdict.requires_human_review is True

    def test_duplicate_outranks_other_failures(self, engine) -> None:
        """Severity ordering — a duplicate is the most consequential finding."""
        result = engine.decide(
            [
                check(CheckName.SIGNATURE_VERIFY, CheckResult.PASS),
                check(CheckName.DUPLICATE_CHECK, CheckResult.FAIL),
                check(CheckName.PROFILE_NAME_MATCH, CheckResult.FAIL),
            ],
            valid_proof(),
        )
        assert result.verdict is Verdict.DUPLICATE

    def test_advisory_checks_never_approve_on_their_own(self, engine) -> None:
        result = engine.decide(
            [check(name, CheckResult.PASS) for name, _ in [(CheckName.OCR_CROSS_CHECK, 0)]],
            None,
        )
        assert result.verdict is not Verdict.VERIFIED


class TestStrictness:
    def test_standard_approves_on_a_warning(self, engine) -> None:
        result = engine.decide(
            [
                check(CheckName.SIGNATURE_VERIFY, CheckResult.PASS),
                check(CheckName.OCR_CROSS_CHECK, CheckResult.WARN),
            ],
            valid_proof(),
        )
        assert result.verdict is Verdict.VERIFIED

    def test_strict_routes_a_warning_to_review(self, strict) -> None:
        result = strict.decide(
            [
                check(CheckName.SIGNATURE_VERIFY, CheckResult.PASS),
                check(CheckName.OCR_CROSS_CHECK, CheckResult.WARN),
            ],
            valid_proof(),
        )
        assert result.verdict is Verdict.TEXT_MISMATCH

    def test_strictness_never_enables_rejection(self, strict) -> None:
        """★ No tenant policy may turn a verdict into an auto-rejection."""
        result = strict.decide(
            [
                check(
                    CheckName.SIGNATURE_VERIFY, CheckResult.FAIL, error=ErrorCode.SIGNATURE_INVALID
                )
            ],
            invalid_proof(),
        )
        assert result.verdict.is_auto_reject is False

    def test_strictness_cannot_approve_without_a_signature(self, strict) -> None:
        lenient = DeterministicVerdictEngine(strictness=Strictness.LENIENT)
        assert lenient.decide([], invalid_proof()).verdict is not Verdict.VERIFIED


# --------------------------------------------------------------------------- #
# ★ The language rule
# --------------------------------------------------------------------------- #


class TestLanguage:
    FORBIDDEN = ("fake", "forg", "fraud", "counterfeit", "criminal", "illegal")

    @pytest.mark.parametrize("verdict", list(Verdict))
    def test_no_message_accuses_the_employee(self, verdict: Verdict) -> None:
        """★ CONTRACTS.md §1. A genuine card photographed badly is not a forgery,
        and the system cannot tell the two apart from the employee's side.
        """
        message = MESSAGES[verdict].lower()
        for word in self.FORBIDDEN:
            assert word not in message, f"{verdict.value} message contains '{word}'"

    @pytest.mark.parametrize("verdict", list(Verdict))
    def test_every_verdict_has_a_message(self, verdict: Verdict) -> None:
        assert MESSAGES[verdict].strip()

    def test_tampered_says_could_not_verify(self, engine) -> None:
        message = MESSAGES[Verdict.TAMPERED].lower()
        assert "could not verify" in message

    def test_review_messages_reassure_the_employee(self) -> None:
        """Being sent to HR is not a failure the person must act on."""
        for verdict in (Verdict.PROFILE_MISMATCH, Verdict.TEXT_MISMATCH):
            assert "no further action" in MESSAGES[verdict].lower()

    def test_unreadable_message_names_the_failing_side(self) -> None:
        """ "Retake the back photo" beats "we could not read the QR code"."""
        checks = {
            CheckName.QR_DECODED: check(
                CheckName.QR_DECODED, CheckResult.FAIL, detail="no QR on: back"
            )
        }
        assert "back" in message_for(Verdict.UNREADABLE, checks)

    def test_verified_with_one_bad_side_explains_itself(self) -> None:
        checks = {CheckName.SIDE_AGREEMENT: check(CheckName.SIDE_AGREEMENT, CheckResult.SKIP)}
        message = message_for(Verdict.VERIFIED, checks)
        assert "verified" in message.lower()
        assert "unclear" in message.lower()


# --------------------------------------------------------------------------- #
# Privacy
# --------------------------------------------------------------------------- #


def _result_with_identity() -> VerificationResult:
    return VerificationResult(
        job_id="job-1",
        verdict=Verdict.VERIFIED,
        proof=valid_proof(),
        identity=AadhaarIdentity(
            name="Test Person",
            dob="01-01-1990",
            gender="M",
            aadhaar_last4="1234",
            reference_id="1234202608131030000",
        ),
        address=AadhaarAddress(district="Jaipur", state="Rajasthan", pincode="302001"),
    )


class TestPrivacy:
    def test_reference_id_is_destroyed(self, privacy) -> None:
        """★ The closest thing to a stable per-person identifier in the QR."""
        result = privacy.apply(_result_with_identity())
        assert result.identity.reference_id == REDACTED
        assert "2026" not in result.identity.reference_id

    def test_reference_hash_is_produced(self, privacy) -> None:
        result = privacy.apply(_result_with_identity())
        assert result.reference_hash is not None
        assert result.reference_hash.startswith("hmac-sha256:")

    def test_hash_is_stable_for_the_same_input(self, privacy) -> None:
        """Duplicate detection depends on this."""
        assert privacy.reference_hash("abc") == privacy.reference_hash("abc")

    def test_hash_differs_across_deployments(self) -> None:
        """★ Two tenants must not be able to correlate the same person."""
        a = DataMinimisingFilter(hash_secret="secret-one")
        b = DataMinimisingFilter(hash_secret="secret-two")
        assert a.reference_hash("1234202608131030000") != b.reference_hash("1234202608131030000")

    def test_hash_verification_is_constant_time(self, privacy) -> None:
        assert privacy.verify_hash("abc", privacy.reference_hash("abc")) is True
        assert privacy.verify_hash("abc", privacy.reference_hash("xyz")) is False

    def test_address_is_stripped_by_default(self, privacy) -> None:
        """An Aadhaar address is a home address. Most HR flows never need it."""
        assert privacy.apply(_result_with_identity()).address is None

    def test_address_can_be_kept_deliberately(self) -> None:
        keeper = DataMinimisingFilter(hash_secret=SECRET, keep_address=True)
        assert keeper.apply(_result_with_identity()).address is not None

    def test_placeholder_secret_is_refused(self) -> None:
        """★ A default secret makes the hash brute-forceable. Fail loudly."""
        with pytest.raises(ValueError, match="hash_secret"):
            DataMinimisingFilter(hash_secret="CHANGE-ME-IN-PRODUCTION")
        with pytest.raises(ValueError):
            DataMinimisingFilter(hash_secret="")

    def test_purge_deadline_is_set(self, privacy) -> None:
        assert privacy.apply(_result_with_identity()).purge_after is not None

    def test_verified_at_is_set_only_on_approval(self, privacy) -> None:
        approved = privacy.apply(_result_with_identity())
        assert approved.verified_at is not None

        rejected = _result_with_identity().model_copy(
            update={"verdict": Verdict.TAMPERED, "proof": invalid_proof()}
        )
        assert privacy.apply(rejected).verified_at is None

    def test_filter_is_idempotent(self, privacy) -> None:
        once = privacy.apply(_result_with_identity())
        twice = privacy.apply(once)
        assert twice.identity.reference_id == REDACTED
        assert twice.reference_hash == once.reference_hash

    def test_identity_survives_minimisation(self, privacy) -> None:
        """What an audit needs, and nothing more."""
        result = privacy.apply(_result_with_identity())
        assert result.identity.name == "Test Person"
        assert result.identity.dob == "01-01-1990"
        assert result.identity.aadhaar_last4 == "1234"

    def test_no_full_aadhaar_number_anywhere(self, privacy) -> None:
        serialised = privacy.apply(_result_with_identity()).model_dump_json()
        assert "1234202608131030000" not in serialised
