"""Synthetic Secure QR payload builder — test fixtures only.

⛔ NOT PRODUCTION CODE. Never imported by anything under ``src/``.

WHY SYNTHETIC FIXTURES ARE THE RIGHT TOOL HERE
----------------------------------------------
Step 1 tests parsing and signature verification. Neither needs a real Aadhaar,
and real cards are actually the *worse* instrument for the job:

* **Deterministic tampering.** We can flip one specific byte at one specific
  offset, re-encode without re-signing, and assert the signature fails. Doing
  that systematically across every field and every boundary is impossible with
  a real card.
* **Every failure path on demand.** Truncated payloads, wrong version markers,
  corrupted gzip, off-by-one signature boundaries, empty trust stores.
* **No personal data, ever.** These tests run in CI forever without a byte of
  real PII in the repository.

Real cards matter only at integration validation (Step 1 exit criterion), which
the project owner runs locally against their own corpus.

The builder replicates the documented UIDAI byte structure exactly:

    text fields (0xFF-delimited) ‖ photo ‖ [hashes] ‖ signature(256)
        → optional gzip
        → big-endian bytes
        → large decimal integer
        → QR string
"""

from __future__ import annotations

import gzip
from dataclasses import dataclass, field, replace

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509 import Certificate

from avs.truststore import UidaiCertificate

__all__ = [
    "DELIMITER_BYTE",
    "FAKE_JP2_HEADER",
    "SyntheticIdentity",
    "SyntheticQrBuilder",
    "make_test_certificate",
    "make_test_keypair",
]

DELIMITER_BYTE = b"\xff"
SIGNATURE_LENGTH = 256

#: Minimal valid-looking JPEG2000 container header, so the parser's photo
#: detection has something realistic to find.
FAKE_JP2_HEADER = b"\x00\x00\x00\x0cjP  \r\n\x87\n"


@dataclass(frozen=True, slots=True)
class SyntheticIdentity:
    """Entirely fictional demographic values.

    ``reference_id`` begins with four digits, mirroring the real format
    (last-4 of the Aadhaar number + a timestamp). No real number is represented.
    """

    reference_id: str = "1234202608131030000"
    name: str = "Test Person"
    dob: str = "01-01-1990"
    gender: str = "M"
    care_of: str = "S/O Test Parent"
    district: str = "Jaipur"
    landmark: str = "Near Test Park"
    house: str = "12-A"
    location: str = "Test Colony"
    pincode: str = "302001"
    post_office: str = "Test PO"
    state: str = "Rajasthan"
    street: str = "Test Marg"
    sub_district: str = "Test Tehsil"
    vtc: str = "Jaipur"


@dataclass
class SyntheticQrBuilder:
    """Builds signed synthetic Secure QR payloads.

    Example:
        >>> private_key, cert = make_test_keypair()
        >>> builder = SyntheticQrBuilder(private_key=private_key)
        >>> qr_string = builder.build()
        >>> tampered = builder.build_tampered(field_name="name", new_value="Someone Else")
    """

    private_key: rsa.RSAPrivateKey
    identity: SyntheticIdentity = field(default_factory=SyntheticIdentity)

    version: str | None = None
    """Optional leading version marker. **Defaults to None — the real format.**

    ⛔ THIS DEFAULT WAS "V2" AND THAT WAS THE ROOT CAUSE OF A LONG BUG HUNT.

       UIDAI's SECURE QR CODE SPECIFICATION (March 2019) §3.1 defines the
       payload as beginning with the email/mobile PRESENCE INDICATOR — "0", "1",
       "2" or "3". There is no version marker field.

       This fixture emitted one anyway, and the parser was written to expect
       one. Fixture and parser agreed with each other and both disagreed with
       reality, so 540 tests passed while real Aadhaar cards failed to parse.
       A test fixture built from the same assumption as the code under test
       proves only that the assumption is self-consistent.

       Verified against UIDAI's own published sample payload, which parses
       correctly with this default.

       Set it to "V2" explicitly to exercise the marker-prefixed variant that
       also occurs in the wild.
    """

    presence: str = "3"  # both mobile and email hashes present
    photo_size: int = 512
    compress: bool = True

    # ------------------------------------------------------------------ #
    # Assembly
    # ------------------------------------------------------------------ #

    def text_fields(self) -> list[str]:
        """Text fields in payload order, matching avs.parser.fields.FIELD_MAPS."""
        i = self.identity
        fields = [
            self.presence,
            i.reference_id,
            i.name,
            i.dob,
            i.gender,
            i.care_of,
            i.district,
            i.landmark,
            i.house,
            i.location,
            i.pincode,
            i.post_office,
            i.state,
            i.street,
            i.sub_district,
            i.vtc,
        ]
        if self.version:
            fields.insert(0, self.version)
        return fields

    def _photo(self) -> bytes:
        body = bytes((idx * 7 + 11) % 256 for idx in range(self.photo_size))
        return FAKE_JP2_HEADER + body

    def _hashes(self) -> bytes:
        count = {"0": 0, "1": 1, "2": 1, "3": 2}.get(self.presence, 0)
        return b"".join(bytes([0xA0 + n] * 32) for n in range(count))

    def unsigned_body(self) -> bytes:
        """Everything that will be signed, before the signature is appended."""
        text = DELIMITER_BYTE.join(f.encode("utf-8") for f in self.text_fields())
        return text + DELIMITER_BYTE + self._photo() + self._hashes()

    def signed_payload(self) -> bytes:
        """Decompressed payload: body ‖ signature(256)."""
        body = self.unsigned_body()
        signature = self.private_key.sign(body, padding.PKCS1v15(), hashes.SHA256())
        assert len(signature) == SIGNATURE_LENGTH, "test key must be RSA-2048"
        return body + signature

    # ------------------------------------------------------------------ #
    # Encoding
    # ------------------------------------------------------------------ #

    @staticmethod
    def encode(payload: bytes, *, compress: bool = True) -> str:
        """payload bytes → optional gzip → big integer → decimal QR string."""
        data = gzip.compress(payload, mtime=0) if compress else payload
        return str(int.from_bytes(data, byteorder="big"))

    def build(self) -> str:
        """A correctly signed, genuine synthetic QR string."""
        return self.encode(self.signed_payload(), compress=self.compress)

    # ------------------------------------------------------------------ #
    # Tampering — the negative corpus
    # ------------------------------------------------------------------ #

    def build_tampered(self, *, field_name: str, new_value: str) -> str:
        """Alter a demographic field WITHOUT re-signing.

        This is exactly what a forger does: take a genuine card, change the name
        or date of birth, and hope nobody checks. The signature was computed over
        the original bytes, so it can no longer match.
        """
        tampered_identity = replace(self.identity, **{field_name: new_value})
        original_signature = self.signed_payload()[-SIGNATURE_LENGTH:]

        clone = SyntheticQrBuilder(
            private_key=self.private_key,
            identity=tampered_identity,
            version=self.version,
            presence=self.presence,
            photo_size=self.photo_size,
            compress=self.compress,
        )
        # New body, OLD signature — the forgery.
        return self.encode(
            clone.unsigned_body() + original_signature,
            compress=self.compress,
        )

    def build_byte_flipped(self, offset: int) -> str:
        """Flip one byte of the signed region without re-signing.

        Used to prove that *any* single-byte change anywhere in the signed data
        breaks verification — not just changes to fields we happen to parse.
        """
        payload = bytearray(self.signed_payload())
        if not 0 <= offset < len(payload) - SIGNATURE_LENGTH:
            raise ValueError("offset must fall inside the signed region")
        payload[offset] ^= 0xFF
        return self.encode(bytes(payload), compress=self.compress)

    def build_photo_swapped(self) -> str:
        """Replace the photograph, keeping the original signature."""
        original = self.signed_payload()
        signature = original[-SIGNATURE_LENGTH:]
        clone = SyntheticQrBuilder(
            private_key=self.private_key,
            identity=self.identity,
            version=self.version,
            presence=self.presence,
            photo_size=self.photo_size,
            compress=self.compress,
        )
        body = bytearray(clone.unsigned_body())
        # Overwrite the tail of the photo block with different pixel data.
        body[-64:] = bytes(range(64))
        return self.encode(bytes(body) + signature, compress=self.compress)

    def build_truncated(self, drop_bytes: int = 300) -> str:
        payload = self.signed_payload()
        return self.encode(payload[:-drop_bytes], compress=self.compress)

    def build_signature_stripped(self) -> str:
        """Body with no signature at all."""
        return self.encode(self.unsigned_body(), compress=self.compress)


# ---------------------------------------------------------------------- #
# Test key material
#
# Generated fresh per test session. No key is ever committed — pre-commit's
# detect-private-key hook enforces this.
# ---------------------------------------------------------------------- #


def make_test_keypair() -> tuple[rsa.RSAPrivateKey, UidaiCertificate]:
    """An RSA-2048 keypair standing in for UIDAI's signing key."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    certificate = make_test_certificate(private_key)
    return private_key, certificate


def make_test_certificate(
    private_key: rsa.RSAPrivateKey,
    *,
    serial: str = "test-serial-001",
    subject: str = "CN=Test UIDAI Signing Key",
) -> UidaiCertificate:
    """Wrap a test public key in the UidaiCertificate shape.

    Builds the struct directly rather than minting an X.509 certificate — the
    verifier only needs the public key, validity window, and identifiers.
    """
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    return UidaiCertificate(
        serial=serial,
        subject=subject,
        public_key=private_key.public_key(),
        not_valid_before=now - timedelta(days=1),
        not_valid_after=now + timedelta(days=365),
        source="synthetic-test-fixture",
    )


def make_expired_certificate(private_key: rsa.RSAPrivateKey) -> UidaiCertificate:
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    return UidaiCertificate(
        serial="test-serial-expired",
        subject="CN=Expired Test Key",
        public_key=private_key.public_key(),
        not_valid_before=now - timedelta(days=800),
        not_valid_after=now - timedelta(days=30),
        source="synthetic-test-fixture",
    )


def _unused_x509_helper(cert: Certificate) -> bytes:  # pragma: no cover
    """Kept so the x509/serialization imports stay meaningful for Step 2."""
    return cert.public_bytes(serialization.Encoding.PEM)
