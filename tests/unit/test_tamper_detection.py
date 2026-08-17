"""★ Tamper detection — the project's central security claim. Step 1.

This suite proves the guarantee the whole system rests on:

    ANY alteration to a signed Aadhaar payload invalidates its signature.
    100% detection. No thresholds. No false negatives. No exceptions.

Every test here should be readable by a non-cryptographer, because these are the
tests you show a client's security team.
"""

from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from avs.contracts import ErrorCode
from avs.crypto import SecureQrVerifier
from avs.parser import SecureQrParser
from avs.parser.fields import SIGNATURE_LENGTH
from tests.fixtures.synthetic import (
    SyntheticQrBuilder,
    make_expired_certificate,
    make_test_certificate,
)


class TestGenuinePayloads:
    """A correctly signed payload must always verify."""

    def test_genuine_payload_verifies(
        self, parser: SecureQrParser, verifier: SecureQrVerifier, builder: SyntheticQrBuilder
    ) -> None:
        proof = verifier.verify(parser.parse(builder.build()))
        assert proof.valid is True
        assert proof.error is None
        assert proof.algorithm == "RSA-2048/SHA-256/PKCS1v15"

    def test_genuine_uncompressed_payload_verifies(
        self, parser: SecureQrParser, verifier: SecureQrVerifier, test_key: rsa.RSAPrivateKey
    ) -> None:
        """UIDAI has shipped both compressed and uncompressed payloads."""
        uncompressed = SyntheticQrBuilder(private_key=test_key, compress=False)
        assert verifier.verify(parser.parse(uncompressed.build())).valid is True

    def test_genuine_legacy_layout_verifies(
        self, parser: SecureQrParser, verifier: SecureQrVerifier, test_key: rsa.RSAPrivateKey
    ) -> None:
        """Older Secure QRs carry no version marker; fields shift by one slot."""
        no_marker = SyntheticQrBuilder(private_key=test_key, version=None)
        payload = parser.parse(no_marker.build())
        assert payload.version == "V1"
        assert payload.identity.name == "Test Person"
        assert verifier.verify(payload).valid is True

    @pytest.mark.parametrize("presence", ["0", "1", "2", "3"])
    def test_all_hash_presence_combinations_verify(
        self,
        parser: SecureQrParser,
        verifier: SecureQrVerifier,
        test_key: rsa.RSAPrivateKey,
        presence: str,
    ) -> None:
        builder = SyntheticQrBuilder(private_key=test_key, presence=presence)
        assert verifier.verify(parser.parse(builder.build())).valid is True

    def test_verification_is_repeatable(
        self, parser: SecureQrParser, verifier: SecureQrVerifier, builder: SyntheticQrBuilder
    ) -> None:
        """No randomness in the verdict — the same input always gives the same answer."""
        qr = builder.build()
        results = [verifier.verify(parser.parse(qr)).valid for _ in range(20)]
        assert results == [True] * 20


class TestFieldTampering:
    """Editing any demographic field breaks the signature. This is the forgery case."""

    @pytest.mark.parametrize(
        ("field_name", "new_value"),
        [
            ("name", "Someone Else"),
            ("name", "Test Persan"),  # a single letter changed
            ("dob", "02-01-1990"),
            ("dob", "01-01-1991"),
            ("gender", "F"),
            ("reference_id", "9999202608131030000"),
            ("district", "Mumbai"),
            ("state", "Maharashtra"),
            ("pincode", "400001"),
            ("house", "99-Z"),
            ("street", "Other Marg"),
            ("care_of", "S/O Other Parent"),
            ("vtc", "Delhi"),
            ("landmark", "Near Other Park"),
            ("location", "Other Colony"),
            ("post_office", "Other PO"),
            ("sub_district", "Other Tehsil"),
        ],
    )
    def test_tampered_field_fails_verification(
        self,
        parser: SecureQrParser,
        verifier: SecureQrVerifier,
        builder: SyntheticQrBuilder,
        field_name: str,
        new_value: str,
    ) -> None:
        qr = builder.build_tampered(field_name=field_name, new_value=new_value)
        proof = verifier.verify(parser.parse(qr))
        assert proof.valid is False, f"tampering with {field_name} was NOT detected"
        assert proof.error is ErrorCode.SIGNATURE_INVALID

    def test_single_character_change_is_detected(
        self, parser: SecureQrParser, verifier: SecureQrVerifier, builder: SyntheticQrBuilder
    ) -> None:
        """'Test Person' → 'Test Persan'. One letter. Still caught."""
        qr = builder.build_tampered(field_name="name", new_value="Test Persan")
        assert verifier.verify(parser.parse(qr)).valid is False

    def test_photo_replacement_is_detected(
        self, parser: SecureQrParser, verifier: SecureQrVerifier, builder: SyntheticQrBuilder
    ) -> None:
        """Swapping the photograph while keeping the signature — caught."""
        assert verifier.verify(parser.parse(builder.build_photo_swapped())).valid is False


class TestByteLevelTampering:
    """Any single byte, anywhere in the signed region, breaks the signature.

    Stronger than field tampering: it proves detection does not depend on the
    parser understanding what changed.
    """

    @pytest.mark.parametrize("offset", [0, 1, 5, 20, 50, 100, 200, 300, 400, 500, 600, 700])
    def test_single_byte_flip_anywhere_is_detected(
        self,
        parser: SecureQrParser,
        verifier: SecureQrVerifier,
        builder: SyntheticQrBuilder,
        offset: int,
    ) -> None:
        signed_length = len(builder.unsigned_body())
        if offset >= signed_length:
            pytest.skip(f"offset {offset} beyond signed region ({signed_length} bytes)")

        qr = builder.build_byte_flipped(offset)
        try:
            payload = parser.parse(qr)
        except Exception:
            # A flipped byte can corrupt the structure badly enough that parsing
            # fails. That is also a rejection — the document never reaches a
            # verdict of VERIFIED, which is what matters.
            return
        assert verifier.verify(payload).valid is False, (
            f"byte flip at offset {offset} was NOT detected"
        )

    def test_exhaustive_sweep_of_first_hundred_bytes(
        self, parser: SecureQrParser, verifier: SecureQrVerifier, builder: SyntheticQrBuilder
    ) -> None:
        """Every one of the first 100 signed bytes, flipped in turn. Zero survivors."""
        survivors = []
        for offset in range(100):
            try:
                payload = parser.parse(builder.build_byte_flipped(offset))
            except Exception:
                continue  # structural rejection — still not approved
            if verifier.verify(payload).valid:
                survivors.append(offset)
        assert survivors == [], f"undetected tampering at offsets: {survivors}"


class TestSignatureBoundary:
    """★ The most dangerous possible bug: an off-by-one in the signed byte range.

    If ``signed_bytes`` were computed over payload[:-255] or payload[:-257], the
    system would produce false verdicts while appearing to work. These tests make
    that failure mode impossible to introduce unnoticed.

    CONTRACTS.md §5.
    """

    def test_signature_boundary_is_exact(
        self, parser: SecureQrParser, builder: SyntheticQrBuilder
    ) -> None:
        raw = builder.signed_payload()
        payload = parser.parse(builder.build())

        assert len(payload.signature) == SIGNATURE_LENGTH
        assert payload.signature == raw[-SIGNATURE_LENGTH:]
        assert payload.signed_bytes == raw[:-SIGNATURE_LENGTH]
        assert payload.signed_bytes + payload.signature == raw
        assert len(payload.signed_bytes) + len(payload.signature) == len(raw)

    def test_shifting_the_boundary_by_one_byte_breaks_verification(
        self,
        parser: SecureQrParser,
        builder: SyntheticQrBuilder,
        test_key: rsa.RSAPrivateKey,
    ) -> None:
        """Proof that the exact range matters — both shifts must fail."""
        payload = parser.parse(builder.build())
        public_key = test_key.public_key()

        # Correct range verifies.
        public_key.verify(
            payload.signature, payload.signed_bytes, padding.PKCS1v15(), hashes.SHA256()
        )

        # One byte short.
        with pytest.raises(InvalidSignature):
            public_key.verify(
                payload.signature,
                payload.signed_bytes[:-1],
                padding.PKCS1v15(),
                hashes.SHA256(),
            )

        # One byte long.
        with pytest.raises(InvalidSignature):
            public_key.verify(
                payload.signature,
                payload.signed_bytes + b"\x00",
                padding.PKCS1v15(),
                hashes.SHA256(),
            )

    def test_signature_stripped_entirely_is_rejected(
        self, parser: SecureQrParser, verifier: SecureQrVerifier, builder: SyntheticQrBuilder
    ) -> None:
        payload = parser.parse(builder.build_signature_stripped())
        assert verifier.verify(payload).valid is False


class TestTrustStoreFailures:
    """Trust-store problems must never produce an approval."""

    def test_wrong_certificate_rejects_genuine_payload(
        self, parser: SecureQrParser, builder: SyntheticQrBuilder
    ) -> None:
        """A payload signed by a different key must not verify."""
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        wrong_verifier = SecureQrVerifier([make_test_certificate(other_key)])
        proof = wrong_verifier.verify(parser.parse(builder.build()))
        assert proof.valid is False
        assert proof.error is ErrorCode.SIGNATURE_INVALID

    def test_empty_trust_store_never_approves(
        self, parser: SecureQrParser, builder: SyntheticQrBuilder
    ) -> None:
        proof = SecureQrVerifier([]).verify(parser.parse(builder.build()))
        assert proof.valid is False
        assert proof.error is ErrorCode.TRUSTSTORE_EMPTY

    def test_expired_certificate_still_rejects_a_tampered_payload(
        self,
        parser: SecureQrParser,
        builder: SyntheticQrBuilder,
        test_key: rsa.RSAPrivateKey,
    ) -> None:
        """★ REVISED in Step 7.5, and this is the version that matters.

        Step 7.5 made lapsed certificates acceptable for verification, because
        refusing them would report genuine pre-rotation cards as TAMPERED. That
        relaxation must not open a hole: a private key does not leak when its
        certificate lapses, so a forgery still fails. Proven, not assumed.
        """
        proof = SecureQrVerifier([make_expired_certificate(test_key)]).verify(
            parser.parse(builder.build_tampered(field_name="name", new_value="Someone Else"))
        )
        assert proof.valid is False

    def test_rotation_correct_certificate_among_wrong_ones(
        self,
        parser: SecureQrParser,
        builder: SyntheticQrBuilder,
        test_key: rsa.RSAPrivateKey,
    ) -> None:
        """The rotation guarantee: the store tries every certificate.

        This is why a hardcoded single certificate would break the service the
        day UIDAI rotates its signing key.
        """
        decoys = [
            make_test_certificate(
                rsa.generate_private_key(public_exponent=65537, key_size=2048),
                serial=f"decoy-{n}",
            )
            for n in range(3)
        ]
        correct = make_test_certificate(test_key, serial="the-real-one")

        # Correct certificate last in the list — must still be found.
        verifier = SecureQrVerifier([*decoys, correct])
        proof = verifier.verify(parser.parse(builder.build()))
        assert proof.valid is True
        assert proof.certificate_serial == "the-real-one"


class TestNoFalseApprovals:
    """The invariant that matters most: nothing invalid is ever approved."""

    def test_no_tampered_variant_is_ever_approved(
        self, parser: SecureQrParser, verifier: SecureQrVerifier, builder: SyntheticQrBuilder
    ) -> None:
        """Sweep every tampering technique. Not one may pass."""
        candidates = [
            builder.build_tampered(field_name="name", new_value="Fraud Person"),
            builder.build_tampered(field_name="dob", new_value="31-12-1999"),
            builder.build_tampered(field_name="gender", new_value="F"),
            builder.build_tampered(field_name="pincode", new_value="110001"),
            builder.build_photo_swapped(),
            builder.build_signature_stripped(),
            builder.build_byte_flipped(10),
            builder.build_byte_flipped(150),
        ]

        approved = []
        for index, qr in enumerate(candidates):
            try:
                if verifier.verify(parser.parse(qr)).valid:
                    approved.append(index)
            except Exception:
                continue  # structural rejection is still a rejection
        assert approved == [], f"tampered payloads wrongly approved: {approved}"
