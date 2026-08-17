"""Secure QR parser tests — Step 1.

Covers correct unpacking and every documented failure path. The parser performs
no verification; its only job is to produce structure plus an exact signed byte
range for ``avs.crypto`` to judge.
"""

from __future__ import annotations

import gzip

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from avs.contracts import ErrorCode, QrPayload
from avs.parser import ParseError, SecureQrParser, detect_version
from avs.parser.fields import FIELD_MAPS, SIGNATURE_LENGTH, EmailMobilePresence
from tests.fixtures.synthetic import SyntheticQrBuilder


class TestSuccessfulParsing:
    def test_extracts_identity_fields(
        self, parser: SecureQrParser, builder: SyntheticQrBuilder
    ) -> None:
        payload = parser.parse(builder.build())
        assert payload.identity.name == "Test Person"
        assert payload.identity.dob == "01-01-1990"
        assert payload.identity.gender == "M"
        assert payload.identity.aadhaar_last4 == "1234"

    def test_extracts_all_address_fields(
        self, parser: SecureQrParser, builder: SyntheticQrBuilder
    ) -> None:
        address = parser.parse(builder.build()).address
        assert address.district == "Jaipur"
        assert address.state == "Rajasthan"
        assert address.pincode == "302001"
        assert address.house == "12-A"
        assert address.street == "Test Marg"
        assert address.vtc == "Jaipur"
        assert address.post_office == "Test PO"
        assert address.sub_district == "Test Tehsil"
        assert address.landmark == "Near Test Park"
        assert address.location == "Test Colony"
        assert address.care_of == "S/O Test Parent"

    def test_last4_is_derived_from_reference_id(
        self, parser: SecureQrParser, builder: SyntheticQrBuilder
    ) -> None:
        payload = parser.parse(builder.build())
        assert payload.identity.aadhaar_last4 == payload.identity.reference_id[:4]

    def test_extracts_photo(self, parser: SecureQrParser, builder: SyntheticQrBuilder) -> None:
        payload = parser.parse(builder.build())
        assert payload.photo is not None
        assert len(payload.photo) > 100

    def test_default_layout_is_the_uidai_spec_layout(
        self, parser: SecureQrParser, builder: SyntheticQrBuilder
    ) -> None:
        """★ The default fixture must look like a REAL card, not like our old
        assumption.

        UIDAI SECURE QR CODE SPECIFICATION (March 2019) §3.1: the payload begins
        with the email/mobile presence indicator. There is no version marker.
        This fixture used to emit one, the parser expected one, and the two
        agreed with each other while both disagreed with every real card.
        """
        assert parser.parse(builder.build()).version == "V1"

    def test_detects_an_explicit_version_marker(
        self, parser: SecureQrParser, test_key: rsa.RSAPrivateKey
    ) -> None:
        """Marker-prefixed cards also exist in the wild and must still work."""
        marked = SyntheticQrBuilder(private_key=test_key, version="V2")
        payload = parser.parse(marked.build())
        assert payload.version == "V2"
        assert payload.identity.name == "Test Person"
        assert payload.address.state == "Rajasthan"

    def test_handles_missing_version_marker(
        self, parser: SecureQrParser, test_key: rsa.RSAPrivateKey
    ) -> None:
        builder = SyntheticQrBuilder(private_key=test_key, version=None)
        payload = parser.parse(builder.build())
        assert payload.version == "V1"
        assert payload.identity.name == "Test Person"
        assert payload.address.state == "Rajasthan"

    @pytest.mark.parametrize("compress", [True, False])
    def test_handles_compressed_and_uncompressed(
        self, parser: SecureQrParser, test_key: rsa.RSAPrivateKey, compress: bool
    ) -> None:
        builder = SyntheticQrBuilder(private_key=test_key, compress=compress)
        assert parser.parse(builder.build()).identity.name == "Test Person"

    def test_returns_a_contract_model(
        self, parser: SecureQrParser, builder: SyntheticQrBuilder
    ) -> None:
        assert isinstance(parser.parse(builder.build()), QrPayload)


class TestHashExtraction:
    @pytest.mark.parametrize(
        ("presence", "expect_mobile", "expect_email"),
        [("0", False, False), ("1", False, True), ("2", True, False), ("3", True, True)],
    )
    def test_optional_hashes(
        self,
        parser: SecureQrParser,
        test_key: rsa.RSAPrivateKey,
        presence: str,
        expect_mobile: bool,
        expect_email: bool,
    ) -> None:
        builder = SyntheticQrBuilder(private_key=test_key, presence=presence)
        payload = parser.parse(builder.build())
        assert (payload.mobile_hash is not None) is expect_mobile
        assert (payload.email_hash is not None) is expect_email

    def test_presence_helper_counts(self) -> None:
        assert EmailMobilePresence.hash_count("0") == 0
        assert EmailMobilePresence.hash_count("1") == 1
        assert EmailMobilePresence.hash_count("2") == 1
        assert EmailMobilePresence.hash_count("3") == 2


class TestSignatureExtraction:
    def test_signature_is_exactly_256_bytes(
        self, parser: SecureQrParser, builder: SyntheticQrBuilder
    ) -> None:
        assert len(parser.parse(builder.build()).signature) == SIGNATURE_LENGTH

    def test_signed_bytes_exclude_the_signature(
        self, parser: SecureQrParser, builder: SyntheticQrBuilder
    ) -> None:
        raw = builder.signed_payload()
        payload = parser.parse(builder.build())
        assert payload.signed_bytes == raw[:-SIGNATURE_LENGTH]
        assert len(payload.signed_bytes) == len(raw) - SIGNATURE_LENGTH


class TestFailurePaths:
    def test_empty_payload(self, parser: SecureQrParser) -> None:
        with pytest.raises(ParseError) as exc:
            parser.parse("")
        assert exc.value.code is ErrorCode.PAYLOAD_MALFORMED

    def test_whitespace_only_payload(self, parser: SecureQrParser) -> None:
        with pytest.raises(ParseError):
            parser.parse("   \n  ")

    def test_non_numeric_payload(self, parser: SecureQrParser) -> None:
        with pytest.raises(ParseError) as exc:
            parser.parse("this is not a secure qr payload")
        assert exc.value.code is ErrorCode.PAYLOAD_MALFORMED

    def test_legacy_xml_qr_is_identified(self, parser: SecureQrParser) -> None:
        """Pre-2018 QRs carry XML and are unsigned — they must be named as such,
        not reported as tampered. A genuine old card is not a forgery.
        """
        legacy = '<?xml version="1.0"?><PrintLetterBarcodeData uid="x" name="y"/>'
        with pytest.raises(ParseError) as exc:
            parser.parse(legacy)
        assert exc.value.code is ErrorCode.PAYLOAD_LEGACY_UNSIGNED
        assert exc.value.is_legacy is True

    def test_too_short_payload(self, parser: SecureQrParser) -> None:
        with pytest.raises(ParseError) as exc:
            parser.parse("12345")
        assert exc.value.code is ErrorCode.PAYLOAD_TRUNCATED

    def test_truncated_payload(self, parser: SecureQrParser, builder: SyntheticQrBuilder) -> None:
        with pytest.raises(ParseError):
            parser.parse(builder.build_truncated(drop_bytes=700))

    def test_corrupt_gzip_stream(self, parser: SecureQrParser) -> None:
        broken = bytearray(gzip.compress(b"x" * 600, mtime=0))
        broken[20:40] = b"\x00" * 20
        with pytest.raises(ParseError):
            parser.parse(str(int.from_bytes(bytes(broken), "big")))

    def test_no_delimiters_at_all(self, parser: SecureQrParser) -> None:
        with pytest.raises(ParseError):
            parser.parse(str(int.from_bytes(b"A" * 600, "big")))

    def test_reference_id_without_leading_digits(
        self, parser: SecureQrParser, test_key: rsa.RSAPrivateKey
    ) -> None:
        from dataclasses import replace as dc_replace

        from tests.fixtures.synthetic import SyntheticIdentity

        bad = dc_replace(SyntheticIdentity(), reference_id="ABCD202608131030")
        builder = SyntheticQrBuilder(private_key=test_key, identity=bad)
        with pytest.raises(ParseError) as exc:
            parser.parse(builder.build())
        assert exc.value.code is ErrorCode.PAYLOAD_MALFORMED

    def test_empty_name_is_rejected(
        self, parser: SecureQrParser, test_key: rsa.RSAPrivateKey
    ) -> None:
        from dataclasses import replace as dc_replace

        from tests.fixtures.synthetic import SyntheticIdentity

        bad = dc_replace(SyntheticIdentity(), name="")
        builder = SyntheticQrBuilder(private_key=test_key, identity=bad)
        with pytest.raises(ParseError):
            parser.parse(builder.build())


class TestVersionDispatch:
    @pytest.mark.parametrize("marker", ["V2", "V3", "V4", "v2"])
    def test_known_markers_use_the_v2_layout(self, marker: str) -> None:
        assert detect_version(marker) == "V2"

    @pytest.mark.parametrize("first_field", ["0", "1", "2", "3", "anything-else"])
    def test_absent_marker_falls_back_to_v1(self, first_field: str) -> None:
        assert detect_version(first_field) == "V1"

    def test_field_maps_differ_by_exactly_the_version_slot(self) -> None:
        assert len(FIELD_MAPS["V2"]) == len(FIELD_MAPS["V1"]) + 1
        assert FIELD_MAPS["V2"][0] == "_version"
        assert FIELD_MAPS["V2"][1:] == FIELD_MAPS["V1"]

    def test_every_map_contains_the_required_fields(self) -> None:
        required = {"reference_id", "name", "dob", "gender"}
        for version, mapping in FIELD_MAPS.items():
            assert required <= set(mapping), f"{version} is missing required fields"


class TestPrivacy:
    """CONTRACTS.md §4 and §10 — sensitive values must not leak through repr."""

    def test_repr_hides_signature_and_photo(
        self, parser: SecureQrParser, builder: SyntheticQrBuilder
    ) -> None:
        text = repr(parser.parse(builder.build()))
        assert "signature" not in text or "signed_bytes=" not in text
        assert "photo=" not in text

    def test_no_full_aadhaar_number_is_produced(
        self, parser: SecureQrParser, builder: SyntheticQrBuilder
    ) -> None:
        identity = parser.parse(builder.build()).identity
        assert len(identity.aadhaar_last4) == 4
        assert not hasattr(identity, "aadhaar_number")


# --------------------------------------------------------------------------- #
# Leading-zero recovery — Step 7.5
#
# ⛔ The most dangerous class of bug in this project: one that turns a GENUINE
#    Aadhaar into a TAMPERED verdict. The Secure QR is a decimal integer, and
#    `int()` cannot preserve a leading 0x00. Losing one shifts signed_bytes and
#    the signature no longer matches.
# --------------------------------------------------------------------------- #


def test_decimal_representation_cannot_hold_a_leading_zero():
    """Documents the underlying arithmetic fact the recovery exists for."""
    original = bytes([0x00, 0x1F, 0x8B, 0x08, 0x11, 0x22])
    value = int.from_bytes(original, "big")
    naive = value.to_bytes((value.bit_length() + 7) // 8, "big")

    assert naive != original
    assert naive == original[1:], "the leading zero is gone, not corrupted"


def test_payload_with_a_leading_zero_byte_still_parses(test_key):
    """★ A genuine card must not be lost to an encoding artefact."""
    from tests.fixtures.synthetic import SyntheticQrBuilder

    builder = SyntheticQrBuilder(private_key=test_key)
    parser = SecureQrParser()

    # Force the byte array to begin with 0x00, then re-encode as the decimal
    # integer a real QR would carry — which silently drops that byte.
    raw = builder.build()
    payload_bytes = int(raw).to_bytes((int(raw).bit_length() + 7) // 8, "big")
    with_zero = b"\x00" + payload_bytes
    as_decimal = str(int.from_bytes(with_zero, "big"))

    parsed = parser.parse(as_decimal)
    assert parsed.identity.name
    assert len(parsed.signature) == 256


def test_leading_zero_recovery_does_not_accept_a_forgery(test_key, test_certificate):
    """The recovery must not become a way for a tampered payload to slip through.

    Trying several byte-lengths is only safe because every candidate is verified
    against UIDAI's key. A tamper must fail under all of them.
    """
    from avs.crypto import SecureQrVerifier
    from tests.fixtures.synthetic import SyntheticQrBuilder

    builder = SyntheticQrBuilder(private_key=test_key)
    tampered = builder.build_tampered(field_name="name", new_value="Someone Else")

    parsed = SecureQrParser().parse(tampered)
    proof = SecureQrVerifier([test_certificate]).verify(parsed)

    assert proof.valid is False, "a tampered payload verified — the security gate is broken"


# --------------------------------------------------------------------------- #
# Non-ASCII names — Step 7.5
#
# ⛔ FOUND ON REAL CARDS. `_split_fields` decoded every chunk as UTF-8 and broke
#    out of the loop on UnicodeDecodeError, believing it had reached the binary
#    photo block. UIDAI encodes the Secure QR text fields as ISO-8859-1, so any
#    name with a byte above 0x7F killed the FIRST field and produced the
#    misleading error "no delimited fields found".
#
#    On the real corpus this destroyed 3 of 5 successfully decoded cards. Only
#    pure-ASCII names survived — which in India is a minority.
# --------------------------------------------------------------------------- #


def test_non_ascii_name_does_not_break_field_splitting(test_key):
    """A name with a high byte must parse, not vanish."""
    from tests.fixtures.synthetic import SyntheticIdentity, SyntheticQrBuilder

    builder = SyntheticQrBuilder(
        private_key=test_key,
        identity=SyntheticIdentity(name="Ren\xe9 D'Souza"),  # é = 0xE9 in ISO-8859-1
    )
    parsed = SecureQrParser().parse(builder.build())

    assert parsed.identity.name, "the name field came back empty"
    assert parsed.identity.dob, "field splitting stopped early"
    assert parsed.address.state, "later fields were lost"


def test_iso_8859_1_bytes_are_not_mistaken_for_the_photo_block(test_key):
    """The binary tail must be found structurally, never by a decode failure."""
    from tests.fixtures.synthetic import SyntheticIdentity, SyntheticQrBuilder

    builder = SyntheticQrBuilder(
        private_key=test_key,
        identity=SyntheticIdentity(name="\xc0\xc1\xc2 Test"),
    )
    parsed = SecureQrParser().parse(builder.build())

    assert len(parsed.signature) == 256, "the signature block was misplaced"
    assert parsed.identity.aadhaar_last4.isdigit()


def test_non_ascii_payload_still_verifies(test_key, test_certificate):
    """⛔ The decode change must not disturb the security invariant.

    Field decoding happens after the signed byte range is taken, so the
    signature must be unaffected. Proven, not assumed.
    """
    from avs.crypto import SecureQrVerifier
    from tests.fixtures.synthetic import SyntheticIdentity, SyntheticQrBuilder

    builder = SyntheticQrBuilder(
        private_key=test_key, identity=SyntheticIdentity(name="Ren\xe9 D'Souza")
    )
    parsed = SecureQrParser().parse(builder.build())

    assert SecureQrVerifier([test_certificate]).verify(parsed).valid is True
