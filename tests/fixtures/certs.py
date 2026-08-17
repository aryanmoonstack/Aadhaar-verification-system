"""Real X.509 certificate generation for trust-store tests — fixtures only.

⛔ NOT PRODUCTION CODE.

Step 2 tests need genuine X.509 files on disk (PEM and DER) so that loading,
fingerprinting, deduplication, and pinning are exercised against real
certificate encoding rather than a hand-built struct.

Every key here is generated fresh per test and never written to the repository.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

__all__ = [
    "build_x509",
    "fingerprint_of",
    "make_cert_dir",
    "write_certificate",
]


def build_x509(
    private_key: rsa.RSAPrivateKey,
    *,
    common_name: str = "Test UIDAI Signing Key",
    valid_from_days: int = -1,
    valid_to_days: int = 365,
    serial: int | None = None,
) -> x509.Certificate:
    """A self-signed certificate standing in for a UIDAI signing certificate."""
    now = datetime.now(timezone.utc)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AVS Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(serial if serial is not None else x509.random_serial_number())
        .not_valid_before(now + timedelta(days=valid_from_days))
        .not_valid_after(now + timedelta(days=valid_to_days))
    )
    return builder.sign(private_key, hashes.SHA256())


def write_certificate(
    cert: x509.Certificate,
    path: Path,
    *,
    encoding: str = "pem",
) -> Path:
    """Write a certificate to disk as PEM or DER."""
    enc = serialization.Encoding.PEM if encoding == "pem" else serialization.Encoding.DER
    path.write_bytes(cert.public_bytes(enc))
    return path


def fingerprint_of(cert: x509.Certificate) -> str:
    """Lowercase hex SHA-256 — matches UidaiCertificate.fingerprint_sha256."""
    return cert.fingerprint(hashes.SHA256()).hex()


def make_cert_dir(
    tmp_path: Path,
    *,
    count: int = 1,
    valid_to_days: int = 365,
    encoding: str = "pem",
) -> tuple[Path, list[x509.Certificate]]:
    """Create a directory holding ``count`` freshly generated certificates."""
    cert_dir = tmp_path / "certs"
    cert_dir.mkdir(exist_ok=True)

    certificates: list[x509.Certificate] = []
    for index in range(count):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = build_x509(
            key,
            common_name=f"Test Key {index}",
            valid_to_days=valid_to_days,
        )
        suffix = "pem" if encoding == "pem" else "cer"
        write_certificate(cert, cert_dir / f"cert{index}.{suffix}", encoding=encoding)
        certificates.append(cert)

    return cert_dir, certificates
