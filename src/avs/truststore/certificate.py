"""UIDAI certificate wrapper.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 1 (minimal — avs.crypto needs the type)
Extended : Step 2 adds file loading, rotation handling, expiry monitoring, CLI
Provides : UidaiCertificate, InMemoryCertificateStore
Consumes : cryptography
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509 import Certificate, load_der_x509_certificate, load_pem_x509_certificate

__all__ = ["InMemoryCertificateStore", "UidaiCertificate", "load_certificate_file"]


@dataclass(frozen=True, slots=True)
class UidaiCertificate:
    """A public certificate used to verify Secure QR signatures.

    Public keys only — a private key must never enter this repository.
    """

    serial: str
    subject: str
    public_key: RSAPublicKey
    not_valid_before: datetime
    not_valid_after: datetime
    source: str = "unknown"
    fingerprint_sha256: str = ""
    """Lowercase hex SHA-256 of the DER encoding.

    This is the value to check against UIDAI's published fingerprint before
    adding a certificate, and the value ``FINGERPRINTS.txt`` pins against.
    Empty only for in-memory test certificates that never touch pinning.
    """

    @classmethod
    def from_x509(cls, cert: Certificate, source: str = "unknown") -> UidaiCertificate:
        public_key = cert.public_key()
        if not isinstance(public_key, RSAPublicKey):
            raise TypeError("Secure QR signatures require an RSA public key")
        return cls(
            serial=format(cert.serial_number, "x"),
            subject=cert.subject.rfc4514_string(),
            public_key=public_key,
            not_valid_before=cert.not_valid_before_utc,
            not_valid_after=cert.not_valid_after_utc,
            source=source,
            fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex(),
        )

    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.not_valid_after

    @property
    def days_to_expiry(self) -> int:
        return (self.not_valid_after - datetime.now(timezone.utc)).days


class InMemoryCertificateStore:
    """Minimal certificate store. Step 2 replaces this with the file-backed one.

    Implements avs.contracts.CertificateStore.
    """

    def __init__(self, certificates: list[UidaiCertificate] | None = None) -> None:
        self._certificates = list(certificates or [])

    def certificates(self) -> list[UidaiCertificate]:  # type: ignore[override]
        return list(self._certificates)

    def days_to_earliest_expiry(self) -> int | None:
        if not self._certificates:
            return None
        return min(c.days_to_expiry for c in self._certificates)

    def add(self, certificate: UidaiCertificate) -> None:
        self._certificates.append(certificate)

    def __len__(self) -> int:
        return len(self._certificates)


def load_certificate_file(path: Path | str) -> UidaiCertificate:
    """Load a single X.509 certificate from a .cer/.crt/.pem file.

    Handles both PEM and DER encodings — UIDAI publishes DER-encoded ``.cer``
    files, while most tooling emits PEM.

    Step 2 builds directory-wide loading, rotation handling, and expiry
    alerting on top of this.
    """
    path = Path(path)
    raw = path.read_bytes()

    try:
        cert = load_pem_x509_certificate(raw)
    except ValueError:
        try:
            cert = load_der_x509_certificate(raw)
        except ValueError as exc:
            raise ValueError(f"{path.name} is neither PEM nor DER encoded") from exc

    return UidaiCertificate.from_x509(cert, source=path.name)
