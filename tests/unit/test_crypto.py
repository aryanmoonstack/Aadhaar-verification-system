"""Signature verifier tests — Step 1.

Behavioural contract of ``avs.crypto``:

* Always returns a ``SignatureProof`` — an invalid signature is a normal outcome,
  not an exception.
* Never raises for a tampered document.
* Never approves when the trust store is empty, expired, or wrong.
* Emits the evidence the audit log needs (certificate serial, byte length).
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from avs.contracts import ErrorCode, SignatureProof
from avs.crypto import SecureQrVerifier
from avs.parser import SecureQrParser
from avs.truststore import InMemoryCertificateStore, UidaiCertificate
from tests.fixtures.synthetic import (
    SyntheticQrBuilder,
    make_expired_certificate,
    make_test_certificate,
)


class TestVerifierBehaviour:
    def test_always_returns_a_proof_never_raises(
        self, parser: SecureQrParser, verifier: SecureQrVerifier, builder: SyntheticQrBuilder
    ) -> None:
        for qr in (
            builder.build(),
            builder.build_tampered(field_name="name", new_value="X Y"),
            builder.build_photo_swapped(),
        ):
            assert isinstance(verifier.verify(parser.parse(qr)), SignatureProof)

    def test_proof_carries_certificate_evidence(
        self,
        parser: SecureQrParser,
        verifier: SecureQrVerifier,
        builder: SyntheticQrBuilder,
        test_certificate: UidaiCertificate,
    ) -> None:
        proof = verifier.verify(parser.parse(builder.build()))
        assert proof.certificate_serial == test_certificate.serial
        assert proof.certificate_subject == test_certificate.subject
        # V1 is the UIDAI spec layout — see SyntheticQrBuilder.version.
        assert proof.qr_version == "V1"
        assert proof.signed_byte_length > 0

    def test_failed_proof_carries_no_certificate(
        self, parser: SecureQrParser, verifier: SecureQrVerifier, builder: SyntheticQrBuilder
    ) -> None:
        qr = builder.build_tampered(field_name="dob", new_value="09-09-1999")
        proof = verifier.verify(parser.parse(qr))
        assert proof.valid is False
        assert proof.certificate_serial is None

    def test_algorithm_is_fixed(
        self, parser: SecureQrParser, verifier: SecureQrVerifier, builder: SyntheticQrBuilder
    ) -> None:
        """Not negotiated per payload — CONTRACTS.md §5."""
        assert verifier.verify(parser.parse(builder.build())).algorithm == (
            "RSA-2048/SHA-256/PKCS1v15"
        )


class TestTrustStoreHandling:
    def test_empty_store(self, parser: SecureQrParser, builder: SyntheticQrBuilder) -> None:
        proof = SecureQrVerifier([]).verify(parser.parse(builder.build()))
        assert proof.valid is False
        assert proof.error is ErrorCode.TRUSTSTORE_EMPTY

    def test_only_expired_certificates(
        self, parser: SecureQrParser, builder: SyntheticQrBuilder, test_key: rsa.RSAPrivateKey
    ) -> None:
        """★ REVISED in Step 7.5. This test previously asserted the opposite.

        The original assumption — "an expired certificate can never approve" —
        is correct for TLS and wrong for signed documents. An e-Aadhaar keeps
        the signature it was issued with forever, and UIDAI's published list
        shows one unexpired Secure QR certificate against several lapsed ones.

        Under the old rule every card issued before the last rotation would be
        reported TAMPERED: a false accusation of forgery against the majority of
        genuine cards, and a direct breach of CONTRACTS.md §1 Rule 2.

        The signature is a fact about the past; expiry is a fact about today.
        Only the first decides the verdict.
        """
        proof = SecureQrVerifier([make_expired_certificate(test_key)]).verify(
            parser.parse(builder.build())
        )
        assert proof.valid is True
        assert proof.certificate_expired is True
        assert proof.error is None

    def test_expired_plus_valid_certificate_still_verifies(
        self,
        parser: SecureQrParser,
        builder: SyntheticQrBuilder,
        test_key: rsa.RSAPrivateKey,
        test_certificate: UidaiCertificate,
    ) -> None:
        """Rotation in practice: an old expired cert alongside the current one."""
        verifier = SecureQrVerifier([make_expired_certificate(test_key), test_certificate])
        assert verifier.verify(parser.parse(builder.build())).valid is True

    def test_allow_expired_flag_is_opt_in(
        self, parser: SecureQrParser, builder: SyntheticQrBuilder, test_key: rsa.RSAPrivateKey
    ) -> None:
        """The flag now only changes PREFERENCE, never acceptance.

        With it off we still accept a lapsed anchor, but prefer a live one when
        both match — which keeps the audit trail pointing at the current
        certificate.
        """
        expired = make_expired_certificate(test_key)
        assert SecureQrVerifier([expired]).verify(parser.parse(builder.build())).valid is True
        assert (
            SecureQrVerifier([expired], allow_expired=True)
            .verify(parser.parse(builder.build()))
            .valid
            is True
        )

    def test_first_matching_certificate_wins(
        self, parser: SecureQrParser, builder: SyntheticQrBuilder, test_key: rsa.RSAPrivateKey
    ) -> None:
        a = make_test_certificate(test_key, serial="serial-a")
        b = make_test_certificate(test_key, serial="serial-b")
        proof = SecureQrVerifier([a, b]).verify(parser.parse(builder.build()))
        assert proof.certificate_serial == "serial-a"


class TestCertificateModel:
    def test_expiry_helpers(self, test_certificate: UidaiCertificate) -> None:
        assert test_certificate.is_expired is False
        assert test_certificate.days_to_expiry > 300

    def test_expired_certificate_reports_expired(self, test_key: rsa.RSAPrivateKey) -> None:
        expired = make_expired_certificate(test_key)
        assert expired.is_expired is True
        assert expired.days_to_expiry < 0

    def test_certificate_is_immutable(self, test_certificate: UidaiCertificate) -> None:
        """Trust anchors must not be mutable at runtime."""
        with pytest.raises((AttributeError, TypeError)):
            test_certificate.serial = "tampered"  # type: ignore[misc]


class TestInMemoryStore:
    def test_empty_store_reports_no_expiry(self) -> None:
        assert InMemoryCertificateStore().days_to_earliest_expiry() is None

    def test_reports_earliest_expiry(
        self, test_key: rsa.RSAPrivateKey, test_certificate: UidaiCertificate
    ) -> None:
        store = InMemoryCertificateStore([test_certificate, make_expired_certificate(test_key)])
        assert store.days_to_earliest_expiry() < 0
        assert len(store) == 2

    def test_certificates_returns_a_copy(self, test_certificate: UidaiCertificate) -> None:
        """Callers must not be able to mutate the trust store by side effect."""
        store = InMemoryCertificateStore([test_certificate])
        store.certificates().clear()
        assert len(store.certificates()) == 1


class TestLegacyPayloads:
    def test_legacy_unsigned_is_named_not_blamed(
        self, parser: SecureQrParser, verifier: SecureQrVerifier, builder: SyntheticQrBuilder
    ) -> None:
        """An old unsigned card is not a forgery — it reports LEGACY, not INVALID.

        Reporting it as tampered would accuse an employee holding a genuine
        pre-2018 card. CONTRACTS.md §1 Rule 2.
        """
        payload = parser.parse(builder.build())
        legacy = payload.model_copy(update={"is_legacy_unsigned": True})
        proof = verifier.verify(legacy)
        assert proof.valid is False
        assert proof.error is ErrorCode.PAYLOAD_LEGACY_UNSIGNED
        assert proof.error is not ErrorCode.SIGNATURE_INVALID


# --------------------------------------------------------------------------- #
# Certificate expiry must never decide authenticity — Step 7.5
#
# ⛔ UIDAI's own published list shows ONE unexpired Secure QR / offline-eKYC
#    certificate against several lapsed ones. An e-Aadhaar keeps the signature
#    it was issued with forever. If a lapsed anchor meant "invalid", every card
#    issued before the last rotation would be reported TAMPERED — a false
#    accusation of forgery against the majority of real cards.
# --------------------------------------------------------------------------- #


def _certificate_for(private_key, *, expired: bool):
    from datetime import datetime, timedelta, timezone

    from avs.truststore import UidaiCertificate

    now = datetime.now(timezone.utc)
    if expired:
        window = (now - timedelta(days=1500), now - timedelta(days=100))
    else:
        window = (now - timedelta(days=100), now + timedelta(days=365))
    return UidaiCertificate(
        serial="uidai-test",
        subject="CN=UIDAI Secure QR",
        public_key=private_key.public_key(),
        not_valid_before=window[0],
        not_valid_after=window[1],
        source="uidai_offline.cer",
    )


def test_genuine_card_verifies_under_a_lapsed_certificate(test_key, builder):
    """★ The card was signed while UIDAI's key was valid. It is still genuine."""
    payload = SecureQrParser().parse(builder.build())
    lapsed = _certificate_for(test_key, expired=True)

    proof = SecureQrVerifier([lapsed]).verify(payload)

    assert proof.valid is True, (
        "a genuine Aadhaar was rejected because UIDAI rotated its certificate. "
        "Every card issued before the rotation would be reported TAMPERED."
    )
    assert proof.certificate_expired is True, "expiry must still be reported"


def test_expiry_is_reported_but_does_not_change_the_verdict(test_key, builder):
    payload = SecureQrParser().parse(builder.build())

    live = SecureQrVerifier([_certificate_for(test_key, expired=False)]).verify(payload)
    lapsed = SecureQrVerifier([_certificate_for(test_key, expired=True)]).verify(payload)

    assert live.valid == lapsed.valid is True
    assert live.certificate_expired is False
    assert lapsed.certificate_expired is True


def test_a_lapsed_certificate_still_rejects_a_forgery(test_key, builder):
    """⛔ Accepting retired anchors must not become a hole.

    The private key does not leak when a certificate lapses, so a tamper still
    fails — but this has to be proven, not assumed.
    """
    payload = SecureQrParser().parse(
        builder.build_tampered(field_name="name", new_value="Someone Else")
    )
    proof = SecureQrVerifier([_certificate_for(test_key, expired=True)]).verify(payload)

    assert proof.valid is False


def test_a_live_certificate_is_preferred_when_both_match(test_key, builder):
    """Audit clarity: prefer the current anchor when either would do."""
    payload = SecureQrParser().parse(builder.build())
    live = _certificate_for(test_key, expired=False)
    lapsed = _certificate_for(test_key, expired=True)

    proof = SecureQrVerifier([lapsed, live]).verify(payload)

    assert proof.valid is True
    assert proof.certificate_expired is False
