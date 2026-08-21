"""End-to-end document pipeline tests — Step 6. CONTRACTS.md §11.

This is the full stack: ingest → preprocess → decode → parse → verify → rules →
privacy, over **two** card faces producing **one** verdict.

The scenario that matters most is `test_qr_on_the_front_still_verifies`. Aadhaar
QR placement varies by card format, and a system that assumed "QR = back" would
silently fail for a large share of real cards.
"""

from __future__ import annotations

import pytest

from avs.contracts import CardSide, CheckName, CheckResult, ErrorCode, Strictness, Verdict
from avs.crypto import SecureQrVerifier
from avs.pipeline import DocumentVerifier, SideInput
from avs.privacy import DataMinimisingFilter
from tests.fixtures.qr_images import blur, encode_jpeg, render_card
from tests.fixtures.synthetic import (
    SyntheticQrBuilder,
    make_expired_certificate,
    make_test_certificate,
    make_test_keypair,
)

SECRET = "pipeline-test-secret"


@pytest.fixture(scope="module")
def keypair():
    return make_test_keypair()


@pytest.fixture(scope="module")
def payload(keypair) -> str:
    return SyntheticQrBuilder(private_key=keypair[0]).build()


@pytest.fixture(scope="module")
def card_with_qr(payload: str) -> bytes:
    """A card face carrying the Secure QR."""
    return encode_jpeg(render_card(payload))


@pytest.fixture(scope="module")
def card_without_qr() -> bytes:
    """A card face with only text — no QR at all.

    Rendered with a short non-numeric payload so the QR that *is* drawn decodes
    as FOREIGN, which is what a photo of the wrong document looks like.
    """
    return encode_jpeg(render_card("https://example.com/not-an-aadhaar-code"))


def make_verifier(
    keypair, *, strictness=Strictness.STANDARD, certificates=None, budget: float = 2.0
):
    """A verifier with a deliberately tight budget.

    Production defaults to 12 s for the whole document. Tests use 2 s so the
    suite stays fast — the failure paths would otherwise burn the full variant
    matrix twice per case.
    """
    certs = keypair[1:2] if certificates is None else certificates
    return DocumentVerifier(
        SecureQrVerifier(certs),
        DataMinimisingFilter(hash_secret=SECRET),
        strictness=strictness,
        time_budget_seconds=budget,
    )


def sides(front: bytes, back: bytes) -> list[SideInput]:
    return [SideInput(CardSide.FRONT, front), SideInput(CardSide.BACK, back)]


# --------------------------------------------------------------------------- #
# ★ QR placement — the assumption that would have broken real cards
# --------------------------------------------------------------------------- #


class TestQrPlacement:
    def test_qr_on_the_back_verifies(self, keypair, card_with_qr, card_without_qr) -> None:
        result = make_verifier(keypair).verify(sides(card_without_qr, card_with_qr))
        assert result.verdict is Verdict.VERIFIED

    def test_qr_on_the_front_still_verifies(self, keypair, card_with_qr, card_without_qr) -> None:
        """★ Never assume "QR = back".

        PVC cards carry the Secure QR on the back; the classic printed letter
        often carries it on the front. Hardcoding either would fail for a large
        share of genuine cards.
        """
        result = make_verifier(keypair).verify(sides(card_with_qr, card_without_qr))
        assert result.verdict is Verdict.VERIFIED

    def test_qr_on_both_sides_verifies(self, keypair, card_with_qr) -> None:
        result = make_verifier(keypair).verify(sides(card_with_qr, card_with_qr))
        assert result.verdict is Verdict.VERIFIED

    def test_neither_side_has_a_qr(self, keypair, card_without_qr) -> None:
        result = make_verifier(keypair).verify(sides(card_without_qr, card_without_qr))
        assert result.verdict in {Verdict.UNREADABLE, Verdict.WRONG_DOCUMENT}
        assert result.is_auto_approve is False


# --------------------------------------------------------------------------- #
# Side agreement
# --------------------------------------------------------------------------- #


class TestSideAgreement:
    def test_matching_payloads_pass(self, keypair, card_with_qr) -> None:
        result = make_verifier(keypair).verify(sides(card_with_qr, card_with_qr))
        agreement = next(c for c in result.checks if c.name is CheckName.SIDE_AGREEMENT)
        assert agreement.result is CheckResult.PASS

    def test_different_payloads_route_to_review(self, keypair) -> None:
        """★ Two different Secure QRs means the faces came from different cards.

        Each signature is individually valid — this is exactly the assembled
        forgery a per-image check would wave through.
        """
        key = keypair[0]
        first = encode_jpeg(render_card(SyntheticQrBuilder(private_key=key).build()))
        other_identity = SyntheticQrBuilder(private_key=key)
        from dataclasses import replace

        from tests.fixtures.synthetic import SyntheticIdentity

        other_identity.identity = replace(SyntheticIdentity(), name="Different Person")
        second = encode_jpeg(render_card(other_identity.build()))

        result = make_verifier(keypair).verify(sides(first, second))
        assert result.verdict is Verdict.TEXT_MISMATCH
        assert result.verdict.requires_human_review is True
        assert result.is_auto_approve is False

    def test_single_qr_skips_the_comparison(self, keypair, card_with_qr, card_without_qr) -> None:
        """Normal for a PVC card — nothing to compare, not a failure."""
        result = make_verifier(keypair).verify(sides(card_without_qr, card_with_qr))
        agreement = next(c for c in result.checks if c.name is CheckName.SIDE_AGREEMENT)
        assert agreement.result is CheckResult.SKIP


# --------------------------------------------------------------------------- #
# ★ One side unreadable — the policy decision
# --------------------------------------------------------------------------- #


class TestOneSideUnreadable:
    def test_standard_approves_when_the_qr_verifies(self, keypair, card_with_qr) -> None:
        """★ The signature is cryptographic proof. It does not become less true
        because the second photograph was blurry.
        """
        unusable = encode_jpeg(blur(render_card("x" * 40), 6.0))
        result = make_verifier(keypair).verify(sides(unusable, card_with_qr))
        assert result.verdict is Verdict.VERIFIED

    def test_the_failing_side_is_recorded_for_review(self, keypair, card_with_qr) -> None:
        unusable = b"\xff\xd8\xff" + b"\x00" * 100  # too small, fails ingest
        result = make_verifier(keypair).verify(sides(unusable, card_with_qr))

        front = next(s for s in result.sides if s.side is CardSide.FRONT)
        back = next(s for s in result.sides if s.side is CardSide.BACK)
        assert front.ingested is False
        assert front.error is not None
        assert back.decoded is True

    def test_message_explains_the_unclear_photo(self, keypair, card_with_qr) -> None:
        unusable = b"\xff\xd8\xff" + b"\x00" * 100
        result = make_verifier(keypair).verify(sides(unusable, card_with_qr))
        assert "unclear" in result.user_message.lower()

    def test_both_sides_unusable_is_not_approved(self, keypair) -> None:
        """★ UNREADABLE, not ERROR.

        ERROR means WE are broken and the employee should wait. A rejected
        upload is a retry with a different photo — telling someone to wait for a
        fix that is never coming is worse than useless.
        """
        junk = b"\xff\xd8\xff" + b"\x00" * 100
        result = make_verifier(keypair).verify(sides(junk, junk))
        assert result.verdict is Verdict.UNREADABLE
        assert result.is_auto_approve is False

        # ⚠ The message names the ACTUAL fault now, not one generic sentence for
        #   every ingest failure. `junk` is 103 bytes, so FILE_TOO_SMALL is
        #   right — and it is better advice than the old "could not open your
        #   photos", which described a problem this file does not have.
        message = result.user_message.lower()
        assert "too small" in message
        assert "please" in message


# --------------------------------------------------------------------------- #
# Tampering, end to end
# --------------------------------------------------------------------------- #


class TestTampering:
    def test_edited_field_is_detected_through_the_full_pipeline(
        self, keypair, card_without_qr
    ) -> None:
        """★ The project's central claim, exercised end to end from image bytes."""
        builder = SyntheticQrBuilder(private_key=keypair[0])
        forged = builder.build_tampered(field_name="name", new_value="Someone Else")
        back = encode_jpeg(render_card(forged))

        result = make_verifier(keypair).verify(sides(card_without_qr, back))
        assert result.verdict is Verdict.TAMPERED
        assert result.is_auto_approve is False
        assert "could not verify" in result.user_message.lower()

    def test_card_signed_by_the_wrong_key_is_detected(self, keypair, card_without_qr) -> None:
        from cryptography.hazmat.primitives.asymmetric import rsa

        attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        forged = SyntheticQrBuilder(private_key=attacker_key).build()
        back = encode_jpeg(render_card(forged))

        result = make_verifier(keypair).verify(sides(card_without_qr, back))
        assert result.verdict is Verdict.TAMPERED


# --------------------------------------------------------------------------- #
# Service faults
# --------------------------------------------------------------------------- #


class TestServiceFaults:
    def test_empty_trust_store_is_error_not_tampered(self, keypair, card_with_qr) -> None:
        """★ A missing certificate is our problem. Never blame the employee."""
        broken = DocumentVerifier(SecureQrVerifier([]), DataMinimisingFilter(hash_secret=SECRET))
        result = broken.verify(sides(card_with_qr, card_with_qr))
        assert result.verdict is Verdict.ERROR
        assert result.verdict is not Verdict.TAMPERED

    def test_lapsed_certificate_still_verifies_a_genuine_document(
        self, keypair, card_with_qr
    ) -> None:
        """★ REVISED in Step 7.5. Previously asserted ERROR.

        A lapsed certificate used to be treated as a service fault, which was
        the least-bad outcome under the old rule that expiry invalidated a
        signature. That rule was wrong for signed documents: UIDAI rotates its
        Secure QR certificate every few years and an e-Aadhaar keeps the
        signature it was issued with. Under the old behaviour every card issued
        before the last rotation returned ERROR — the service refusing to
        approve the majority of genuine cards.

        The document is genuine, so the verdict is VERIFIED. The lapsed anchor
        is surfaced on the proof for operations and audit.
        """
        expired = DocumentVerifier(
            SecureQrVerifier([make_expired_certificate(keypair[0])]),
            DataMinimisingFilter(hash_secret=SECRET),
        )
        result = expired.verify(sides(card_with_qr, card_with_qr))

        assert result.verdict is Verdict.VERIFIED
        assert result.proof.certificate_expired is True

    def test_readiness_reflects_the_trust_store(self, keypair) -> None:
        assert make_verifier(keypair).is_ready is True
        empty = DocumentVerifier(SecureQrVerifier([]), DataMinimisingFilter(hash_secret=SECRET))
        assert empty.is_ready is False

    def test_rotation_still_verifies(self, keypair, card_with_qr, card_without_qr) -> None:
        decoys = [
            make_test_certificate(
                __import__(
                    "cryptography.hazmat.primitives.asymmetric.rsa", fromlist=["rsa"]
                ).generate_private_key(public_exponent=65537, key_size=2048),
                serial=f"decoy-{n}",
            )
            for n in range(2)
        ]
        rotated = make_verifier(keypair, certificates=[*decoys, keypair[1]])
        assert rotated.verify(sides(card_without_qr, card_with_qr)).verdict is Verdict.VERIFIED


# --------------------------------------------------------------------------- #
# Result shape and privacy
# --------------------------------------------------------------------------- #


class TestResultShape:
    def test_never_raises(self, keypair) -> None:
        """★ An exception would leave the employee with no message and HR with
        no record. Every path must produce a verdict.
        """
        for payload_bytes in (b"", b"not an image", b"\x00" * 5000):
            result = make_verifier(keypair).verify(
                [SideInput(CardSide.FRONT, payload_bytes), SideInput(CardSide.BACK, payload_bytes)]
            )
            assert result.verdict in set(Verdict)

    def test_job_id_is_assigned(self, keypair, card_with_qr, card_without_qr) -> None:
        result = make_verifier(keypair).verify(sides(card_without_qr, card_with_qr))
        assert result.job_id

    def test_supplied_job_id_is_kept(self, keypair, card_with_qr, card_without_qr) -> None:
        result = make_verifier(keypair).verify(
            sides(card_without_qr, card_with_qr), job_id="job-42"
        )
        assert result.job_id == "job-42"

    def test_both_sides_are_reported(self, keypair, card_with_qr, card_without_qr) -> None:
        result = make_verifier(keypair).verify(sides(card_without_qr, card_with_qr))
        assert {s.side for s in result.sides} == {CardSide.FRONT, CardSide.BACK}

    def test_processing_time_is_recorded(self, keypair, card_with_qr, card_without_qr) -> None:
        result = make_verifier(keypair).verify(sides(card_without_qr, card_with_qr))
        assert result.processing_ms > 0

    def test_privacy_is_applied(self, keypair, card_with_qr, card_without_qr) -> None:
        from avs.privacy import REDACTED

        result = make_verifier(keypair).verify(sides(card_without_qr, card_with_qr))
        assert result.identity.reference_id == REDACTED
        assert result.reference_hash is not None
        assert result.address is None
        assert result.purge_after is not None

    def test_no_raw_payload_in_the_result(self, keypair, card_with_qr, card_without_qr, payload):
        """★ The serialised result is what gets stored and logged."""
        result = make_verifier(keypair).verify(sides(card_without_qr, card_with_qr))
        serialised = result.model_dump_json()
        assert payload not in serialised
        assert payload[:200] not in serialised

    def test_checks_carry_the_evidence(self, keypair, card_with_qr, card_without_qr) -> None:
        result = make_verifier(keypair).verify(sides(card_without_qr, card_with_qr))
        names = {c.name for c in result.checks}
        assert CheckName.SIGNATURE_VERIFY in names
        assert CheckName.QR_DECODED in names
        assert CheckName.SIDE_AGREEMENT in names

    def test_signature_check_is_the_approving_one(
        self, keypair, card_with_qr, card_without_qr
    ) -> None:
        result = make_verifier(keypair).verify(sides(card_without_qr, card_with_qr))
        signature = next(c for c in result.checks if c.name is CheckName.SIGNATURE_VERIFY)
        assert signature.result is CheckResult.PASS
        assert result.proof is not None and result.proof.valid is True


class TestStrictnessEndToEnd:
    def test_strict_tenant_still_approves_a_clean_document(
        self, keypair, card_with_qr, card_without_qr
    ) -> None:
        strict = make_verifier(keypair, strictness=Strictness.STRICT)
        assert strict.verify(sides(card_without_qr, card_with_qr)).verdict is Verdict.VERIFIED

    def test_no_strictness_setting_enables_rejection(
        self, keypair, card_with_qr, card_without_qr
    ) -> None:
        for level in Strictness:
            verifier = make_verifier(keypair, strictness=level)
            result = verifier.verify(sides(card_without_qr, card_with_qr))
            assert result.verdict.is_auto_reject is False


class TestBudgetFairness:
    """★ One bad photo must not starve a good one."""

    def test_a_slow_first_side_does_not_starve_the_second(
        self, keypair, card_with_qr, card_without_qr
    ) -> None:
        """The front has no Aadhaar QR and burns its whole share proving it.

        The back must still get enough time to decode. First-come-first-served
        budgeting would hand the front everything and leave the back ~50 ms —
        and since the QR is usually on the side people upload second, that would
        be the common case, not the rare one.
        """
        verifier = make_verifier(keypair, budget=3.0)
        result = verifier.verify(sides(card_without_qr, card_with_qr))

        assert result.verdict is Verdict.VERIFIED
        back = next(s for s in result.sides if s.side is CardSide.BACK)
        assert back.decoded is True

    def test_the_whole_document_stays_within_budget(self, keypair, card_without_qr) -> None:
        import time as _time

        verifier = make_verifier(keypair, budget=2.0)
        started = _time.perf_counter()
        verifier.verify(sides(card_without_qr, card_without_qr))
        elapsed = _time.perf_counter() - started

        # Generous ceiling — the budget bounds decoding, not ingest or encoding.
        assert elapsed < 8.0, f"document took {elapsed:.1f}s against a 2s budget"


class TestErrorCodes:
    def test_ingest_error_is_carried_into_the_side_outcome(self, keypair, card_with_qr) -> None:
        """⚠ Uses a ZIP, not a PDF.

        This test is about an ingest rejection reaching the side outcome — the
        file type was only ever a convenient way to trigger one. It used a PDF
        until PDF became a supported input, at which point it would have been
        asserting a policy it does not care about. A ZIP is still refused and
        keeps the test measuring what its name claims.
        """
        archive = b"PK\x03\x04" + b"0" * 80_000
        result = make_verifier(keypair).verify(sides(archive, card_with_qr))
        front = next(s for s in result.sides if s.side is CardSide.FRONT)
        assert front.error is ErrorCode.UNSUPPORTED_MIME_TYPE
