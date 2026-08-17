"""Directory-backed UIDAI certificate trust store — Step 2.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 2
Provides : FileCertificateStore, TrustStoreHealth, ExpiryStatus
Consumes : avs.truststore.certificate, avs.config
Used by  : avs.crypto (Step 1), avs.health (Step 7), CLI

THE TWO PROBLEMS THIS MODULE EXISTS TO SOLVE
--------------------------------------------

**1. Rotation.** UIDAI rotates its signing certificate. A service pinned to a
single certificate works perfectly until the day it silently stops verifying
every genuine card. The store therefore holds *many* certificates and the
verifier tries each one — see ``SecureQrVerifier``. Certificates are ordered
newest-expiry-first so current cards match on the first attempt.

**2. Trust-store poisoning.** The trust store is the root of trust for the whole
system. Anyone who can write a certificate into ``certs/`` can mint approvals for
documents they signed themselves. Fingerprint pinning (see ``FINGERPRINTS.txt``)
closes this: when the pin file is present, only certificates whose SHA-256
fingerprint is explicitly listed are loaded. Everything else is refused, loudly.

Certificates are loaded from disk at startup and never fetched over the network —
that is what lets AVS run with outbound internet firewalled shut.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from avs.truststore.certificate import UidaiCertificate, load_certificate_file
from avs.truststore.errors import TrustStoreError

__all__ = [
    "CERTIFICATE_SUFFIXES",
    "PIN_FILE_NAME",
    "ExpiryStatus",
    "FileCertificateStore",
    "LoadIssue",
    "TrustStoreHealth",
]

#: File extensions treated as certificates. Anything else in the directory is ignored.
CERTIFICATE_SUFFIXES = frozenset({".cer", ".crt", ".pem", ".der"})

#: Optional pin file. When present, acts as an allow-list of SHA-256 fingerprints.
PIN_FILE_NAME = "FINGERPRINTS.txt"


class ExpiryStatus(str, Enum):
    """Health classification for a certificate or for the store as a whole."""

    OK = "OK"
    WARNING = "WARNING"  # inside the alert window
    EXPIRED = "EXPIRED"
    EMPTY = "EMPTY"  # no usable certificates at all

    @property
    def is_actionable(self) -> bool:
        """Should this page someone?"""
        return self is not ExpiryStatus.OK


@dataclass(frozen=True, slots=True)
class LoadIssue:
    """A file that could not be loaded, or was refused by pinning."""

    filename: str
    reason: str
    fatal: bool = False


@dataclass(frozen=True, slots=True)
class TrustStoreHealth:
    """Everything ops needs to know, in one object.

    Consumed by ``avs certs status`` now and by the ``/ready`` probe in Step 7.
    """

    status: ExpiryStatus
    total: int
    usable: int
    expired: int
    expiring_soon: int
    days_to_earliest_expiry: int | None
    pinning_enabled: bool
    issues: list[LoadIssue] = field(default_factory=list)

    @property
    def is_ready(self) -> bool:
        """Can the service verify anything at all?

        A store with zero usable certificates is not merely degraded — every
        genuine document would be reported as unverifiable. Step 7's readiness
        probe must fail on this.
        """
        return self.usable > 0

    def summary(self) -> str:
        if not self.is_ready:
            return "TRUST STORE EMPTY — no document can be verified"
        parts = [f"{self.usable} usable"]
        if self.expired:
            parts.append(f"{self.expired} expired")
        if self.expiring_soon:
            parts.append(f"{self.expiring_soon} expiring soon")
        if not self.pinning_enabled:
            parts.append("pinning OFF")
        return ", ".join(parts)


class FileCertificateStore:
    """Loads UIDAI certificates from a directory. Implements ``CertificateStore``.

    Example:
        >>> store = FileCertificateStore(Path("certs"))
        >>> store.load()
        >>> verifier = SecureQrVerifier(store.certificates())
    """

    def __init__(
        self,
        cert_dir: Path | str,
        *,
        warn_days: int = 90,
        require_pinning: bool = False,
    ) -> None:
        """
        Args:
            cert_dir: directory holding UIDAI public certificates.
            warn_days: raise a WARNING this many days before the earliest expiry.
                90 days gives ample time to obtain and review a replacement.
            require_pinning: refuse to start unless ``FINGERPRINTS.txt`` exists.
                Recommended in production, where an unpinned trust store means
                anyone with write access to the directory can mint approvals.
        """
        self.cert_dir = Path(cert_dir)
        self.warn_days = warn_days
        self.require_pinning = require_pinning
        self._certificates: list[UidaiCertificate] = []
        self._issues: list[LoadIssue] = []
        self._pins: dict[str, str] | None = None
        self._loaded = False

    # ------------------------------------------------------------------ #
    # Loading
    # ------------------------------------------------------------------ #

    def load(self) -> None:
        """Read every certificate in the directory. Idempotent.

        Raises:
            TrustStoreError: only for conditions that make the service unsafe to
                start — a missing directory, or pinning required but absent.
                Individual unreadable files are recorded as issues, not raised.
        """
        self._certificates = []
        self._issues = []

        if not self.cert_dir.exists():
            raise TrustStoreError(
                f"certificate directory not found: {self.cert_dir}\n"
                f"See certs/README.md for where to obtain UIDAI certificates."
            )

        self._pins = self._load_pins()
        if self.require_pinning and self._pins is None:
            raise TrustStoreError(
                f"pinning is required but {self.cert_dir / PIN_FILE_NAME} is missing.\n"
                f"Without it, any certificate placed in {self.cert_dir} would be trusted."
            )

        seen_serials: dict[str, str] = {}

        for path in sorted(self.cert_dir.iterdir()):
            if not path.is_file() or path.suffix.lower() not in CERTIFICATE_SUFFIXES:
                continue

            try:
                certificate = load_certificate_file(path)
            except (ValueError, TypeError, OSError) as exc:
                self._issues.append(LoadIssue(path.name, str(exc)))
                continue

            if self._pins is not None and certificate.fingerprint_sha256 not in self._pins:
                self._issues.append(
                    LoadIssue(
                        path.name,
                        f"fingerprint {certificate.fingerprint_sha256[:16]}… is not "
                        f"listed in {PIN_FILE_NAME}",
                        fatal=True,
                    )
                )
                continue

            if certificate.serial in seen_serials:
                # The same certificate supplied in both PEM and DER form.
                self._issues.append(
                    LoadIssue(
                        path.name,
                        f"duplicate of {seen_serials[certificate.serial]} (same serial)",
                    )
                )
                continue

            seen_serials[certificate.serial] = path.name
            self._certificates.append(certificate)

        # Newest expiry first: current cards match on the first attempt, and an
        # old rotated-out certificate never shadows the current one.
        self._certificates.sort(key=lambda c: c.not_valid_after, reverse=True)
        self._loaded = True

    def _load_pins(self) -> dict[str, str] | None:
        """Parse ``FINGERPRINTS.txt`` if present. Returns None when absent."""
        pin_file = self.cert_dir / PIN_FILE_NAME
        if not pin_file.exists():
            return None

        pins: dict[str, str] = {}
        for raw_line in pin_file.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            fingerprint = parts[0].lower().replace(":", "")
            label = parts[1] if len(parts) > 1 else ""
            pins[fingerprint] = label
        return pins

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self.load()

    # ------------------------------------------------------------------ #
    # CertificateStore protocol
    # ------------------------------------------------------------------ #

    def certificates(self) -> list[UidaiCertificate]:
        """All loaded certificates, newest expiry first. Returns a copy."""
        self._ensure_loaded()
        return list(self._certificates)

    def usable_certificates(self) -> list[UidaiCertificate]:
        """Certificates still inside their validity window."""
        return [c for c in self.certificates() if not c.is_expired]

    def days_to_earliest_expiry(self) -> int | None:
        """Days until the first *usable* certificate expires.

        Deliberately ignores already-expired certificates: an expired one that is
        kept around for historical verification must not permanently pin this
        value negative and drown the alert in noise.
        """
        usable = self.usable_certificates()
        if not usable:
            return None
        return min(c.days_to_expiry for c in usable)

    # ------------------------------------------------------------------ #
    # Health
    # ------------------------------------------------------------------ #

    def health(self) -> TrustStoreHealth:
        """Full health report for ops, the CLI, and the Step 7 readiness probe."""
        self._ensure_loaded()

        all_certs = self._certificates
        usable = [c for c in all_certs if not c.is_expired]
        expired = [c for c in all_certs if c.is_expired]
        expiring_soon = [c for c in usable if c.days_to_expiry <= self.warn_days]
        earliest = self.days_to_earliest_expiry()

        if not usable:
            status = ExpiryStatus.EMPTY if not all_certs else ExpiryStatus.EXPIRED
        elif expiring_soon or any(i.fatal for i in self._issues):
            status = ExpiryStatus.WARNING
        else:
            status = ExpiryStatus.OK

        return TrustStoreHealth(
            status=status,
            total=len(all_certs),
            usable=len(usable),
            expired=len(expired),
            expiring_soon=len(expiring_soon),
            days_to_earliest_expiry=earliest,
            pinning_enabled=self._pins is not None,
            issues=list(self._issues),
        )

    @property
    def issues(self) -> list[LoadIssue]:
        self._ensure_loaded()
        return list(self._issues)

    def __len__(self) -> int:
        self._ensure_loaded()
        return len(self._certificates)

    def __repr__(self) -> str:
        state = f"{len(self._certificates)} certs" if self._loaded else "not loaded"
        return f"FileCertificateStore({self.cert_dir}, {state})"
