"""Trust store tests — Step 2.

The trust store is the root of trust for the entire system. Two failure modes
matter more than everything else:

1. **Rotation blindness** — a store that holds only one certificate works
   perfectly until UIDAI rotates, then silently rejects every genuine card.
2. **Trust-store poisoning** — anyone who can write to ``certs/`` can add their
   own certificate and mint approvals for documents they signed themselves.

Both are covered below.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from avs.crypto import SecureQrVerifier
from avs.parser import SecureQrParser
from avs.truststore import (
    PIN_FILE_NAME,
    ExpiryStatus,
    FileCertificateStore,
    TrustStoreError,
    UidaiCertificate,
    load_certificate_file,
)
from tests.fixtures.certs import build_x509, fingerprint_of, make_cert_dir, write_certificate
from tests.fixtures.synthetic import SyntheticQrBuilder


def _new_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class TestLoading:
    def test_loads_pem_certificates(self, tmp_path: Path) -> None:
        cert_dir, _ = make_cert_dir(tmp_path, count=3)
        store = FileCertificateStore(cert_dir)
        store.load()
        assert len(store) == 3

    def test_loads_der_certificates(self, tmp_path: Path) -> None:
        """UIDAI publishes DER-encoded .cer files."""
        cert_dir, _ = make_cert_dir(tmp_path, count=2, encoding="der")
        store = FileCertificateStore(cert_dir)
        store.load()
        assert len(store) == 2

    def test_mixed_encodings_load_together(self, tmp_path: Path) -> None:
        cert_dir = tmp_path / "certs"
        cert_dir.mkdir()
        write_certificate(build_x509(_new_key()), cert_dir / "a.pem", encoding="pem")
        write_certificate(build_x509(_new_key()), cert_dir / "b.cer", encoding="der")
        store = FileCertificateStore(cert_dir)
        store.load()
        assert len(store) == 2

    def test_ignores_non_certificate_files(self, tmp_path: Path) -> None:
        cert_dir, _ = make_cert_dir(tmp_path, count=1)
        (cert_dir / "README.md").write_text("documentation")
        (cert_dir / "notes.txt").write_text("scratch")
        store = FileCertificateStore(cert_dir)
        store.load()
        assert len(store) == 1
        assert store.issues == []

    def test_unreadable_file_is_an_issue_not_a_crash(self, tmp_path: Path) -> None:
        """One corrupt file must not take down a store that still works."""
        cert_dir, _ = make_cert_dir(tmp_path, count=2)
        (cert_dir / "corrupt.pem").write_bytes(b"this is not a certificate")

        store = FileCertificateStore(cert_dir)
        store.load()

        assert len(store) == 2, "working certificates must still load"
        assert len(store.issues) == 1
        assert store.issues[0].filename == "corrupt.pem"

    def test_duplicate_serials_are_deduplicated(self, tmp_path: Path) -> None:
        """The same certificate supplied as both PEM and DER."""
        cert_dir = tmp_path / "certs"
        cert_dir.mkdir()
        cert = build_x509(_new_key())
        write_certificate(cert, cert_dir / "same.pem", encoding="pem")
        write_certificate(cert, cert_dir / "same.cer", encoding="der")

        store = FileCertificateStore(cert_dir)
        store.load()

        assert len(store) == 1
        assert any("duplicate" in issue.reason for issue in store.issues)

    def test_missing_directory_raises(self, tmp_path: Path) -> None:
        store = FileCertificateStore(tmp_path / "does-not-exist")
        with pytest.raises(TrustStoreError):
            store.load()

    def test_empty_directory_loads_but_is_not_ready(self, tmp_path: Path) -> None:
        cert_dir = tmp_path / "certs"
        cert_dir.mkdir()
        store = FileCertificateStore(cert_dir)
        store.load()
        assert len(store) == 0
        assert store.health().is_ready is False

    def test_load_is_idempotent(self, tmp_path: Path) -> None:
        cert_dir, _ = make_cert_dir(tmp_path, count=2)
        store = FileCertificateStore(cert_dir)
        store.load()
        store.load()
        assert len(store) == 2

    def test_lazy_loading_on_first_access(self, tmp_path: Path) -> None:
        cert_dir, _ = make_cert_dir(tmp_path, count=1)
        store = FileCertificateStore(cert_dir)
        assert len(store.certificates()) == 1  # load() never called explicitly


class TestOrdering:
    def test_newest_expiry_first(self, tmp_path: Path) -> None:
        """Current cards should match on the first attempt.

        Ordering also stops a rotated-out certificate from shadowing the current
        one in the verifier's first-match-wins loop.
        """
        cert_dir = tmp_path / "certs"
        cert_dir.mkdir()
        write_certificate(build_x509(_new_key(), valid_to_days=30), cert_dir / "soon.pem")
        write_certificate(build_x509(_new_key(), valid_to_days=900), cert_dir / "far.pem")
        write_certificate(build_x509(_new_key(), valid_to_days=365), cert_dir / "mid.pem")

        certificates = FileCertificateStore(cert_dir).certificates()
        days = [c.days_to_expiry for c in certificates]
        assert days == sorted(days, reverse=True)


class TestExpiry:
    def test_expired_certificate_is_reported(self, tmp_path: Path) -> None:
        cert_dir = tmp_path / "certs"
        cert_dir.mkdir()
        write_certificate(
            build_x509(_new_key(), valid_from_days=-800, valid_to_days=-30),
            cert_dir / "old.pem",
        )
        health = FileCertificateStore(cert_dir).health()
        assert health.expired == 1
        assert health.usable == 0
        assert health.status is ExpiryStatus.EXPIRED
        assert health.is_ready is False

    def test_expiring_soon_triggers_warning(self, tmp_path: Path) -> None:
        cert_dir, _ = make_cert_dir(tmp_path, count=1, valid_to_days=45)
        health = FileCertificateStore(cert_dir, warn_days=90).health()
        assert health.status is ExpiryStatus.WARNING
        assert health.expiring_soon == 1
        assert health.is_ready is True, "still usable — a warning is not an outage"

    def test_healthy_store_reports_ok(self, tmp_path: Path) -> None:
        cert_dir, _ = make_cert_dir(tmp_path, count=2, valid_to_days=500)
        health = FileCertificateStore(cert_dir, warn_days=90).health()
        assert health.status is ExpiryStatus.OK
        assert health.status.is_actionable is False

    def test_earliest_expiry_ignores_already_expired(self, tmp_path: Path) -> None:
        """An archived expired certificate must not pin the alert permanently
        negative and drown out a real upcoming expiry.
        """
        cert_dir = tmp_path / "certs"
        cert_dir.mkdir()
        write_certificate(
            build_x509(_new_key(), valid_from_days=-800, valid_to_days=-30),
            cert_dir / "old.pem",
        )
        write_certificate(build_x509(_new_key(), valid_to_days=200), cert_dir / "current.pem")

        store = FileCertificateStore(cert_dir)
        assert store.days_to_earliest_expiry() == pytest.approx(199, abs=2)

    def test_empty_store_has_no_expiry(self, tmp_path: Path) -> None:
        cert_dir = tmp_path / "certs"
        cert_dir.mkdir()
        assert FileCertificateStore(cert_dir).days_to_earliest_expiry() is None


class TestPinning:
    """Fingerprint pinning — defence against trust-store poisoning."""

    def test_pinning_is_off_when_no_pin_file(self, tmp_path: Path) -> None:
        cert_dir, _ = make_cert_dir(tmp_path, count=1)
        assert FileCertificateStore(cert_dir).health().pinning_enabled is False

    def test_pinned_certificate_loads(self, tmp_path: Path) -> None:
        cert_dir, certs = make_cert_dir(tmp_path, count=2)
        (cert_dir / PIN_FILE_NAME).write_text(
            "\n".join(f"{fingerprint_of(c)}  cert{i}.pem" for i, c in enumerate(certs))
        )
        store = FileCertificateStore(cert_dir)
        store.load()
        assert len(store) == 2
        assert store.health().pinning_enabled is True

    def test_unpinned_certificate_is_refused(self, tmp_path: Path) -> None:
        """★ The poisoning defence: an attacker drops a certificate they control
        into certs/. Without its fingerprint in the pin file, it is refused.
        """
        cert_dir, certs = make_cert_dir(tmp_path, count=1)
        rogue = build_x509(_new_key(), common_name="Attacker Key")
        write_certificate(rogue, cert_dir / "rogue.pem")

        (cert_dir / PIN_FILE_NAME).write_text(f"{fingerprint_of(certs[0])}  cert0.pem")

        store = FileCertificateStore(cert_dir)
        store.load()

        assert len(store) == 1, "rogue certificate must not be loaded"
        refused = [i for i in store.issues if i.fatal]
        assert len(refused) == 1
        assert refused[0].filename == "rogue.pem"
        assert store.health().status is ExpiryStatus.WARNING

    def test_pin_file_ignores_comments_and_blanks(self, tmp_path: Path) -> None:
        cert_dir, certs = make_cert_dir(tmp_path, count=1)
        (cert_dir / PIN_FILE_NAME).write_text(
            f"# UIDAI production certificates\n\n   \n{fingerprint_of(certs[0])}  cert0.pem\n"
        )
        assert len(FileCertificateStore(cert_dir)) == 1

    def test_pin_accepts_colon_separated_fingerprints(self, tmp_path: Path) -> None:
        """openssl prints fingerprints as AA:BB:CC — accept that form too."""
        cert_dir, certs = make_cert_dir(tmp_path, count=1)
        raw = fingerprint_of(certs[0])
        colonised = ":".join(raw[i : i + 2] for i in range(0, len(raw), 2)).upper()
        (cert_dir / PIN_FILE_NAME).write_text(f"{colonised}  cert0.pem")
        assert len(FileCertificateStore(cert_dir)) == 1

    def test_require_pinning_refuses_to_start_without_pin_file(self, tmp_path: Path) -> None:
        cert_dir, _ = make_cert_dir(tmp_path, count=1)
        store = FileCertificateStore(cert_dir, require_pinning=True)
        with pytest.raises(TrustStoreError, match="pinning is required"):
            store.load()

    def test_require_pinning_succeeds_with_pin_file(self, tmp_path: Path) -> None:
        cert_dir, certs = make_cert_dir(tmp_path, count=1)
        (cert_dir / PIN_FILE_NAME).write_text(f"{fingerprint_of(certs[0])}  cert0.pem")
        store = FileCertificateStore(cert_dir, require_pinning=True)
        store.load()
        assert len(store) == 1


class TestFingerprints:
    def test_fingerprint_is_computed_on_load(self, tmp_path: Path) -> None:
        cert_dir, certs = make_cert_dir(tmp_path, count=1)
        loaded = FileCertificateStore(cert_dir).certificates()[0]
        assert loaded.fingerprint_sha256 == fingerprint_of(certs[0])
        assert len(loaded.fingerprint_sha256) == 64

    def test_certificate_metadata_is_populated(self, tmp_path: Path) -> None:
        cert_dir, _ = make_cert_dir(tmp_path, count=1)
        cert = FileCertificateStore(cert_dir).certificates()[0]
        assert cert.serial
        assert "Test Key 0" in cert.subject
        assert cert.source == "cert0.pem"
        assert cert.not_valid_after > cert.not_valid_before


class TestCertificateFileLoading:
    def test_rejects_non_rsa_keys(self, tmp_path: Path) -> None:
        """Secure QR signatures are RSA. An EC certificate must be refused."""
        from cryptography.hazmat.primitives.asymmetric import ec

        key = ec.generate_private_key(ec.SECP256R1())
        path = tmp_path / "ec.pem"
        write_certificate(build_x509(key, common_name="EC Key"), path)  # type: ignore[arg-type]

        with pytest.raises(TypeError):
            load_certificate_file(path)

    def test_garbage_file_raises_value_error(self, tmp_path: Path) -> None:
        path = tmp_path / "junk.pem"
        path.write_bytes(b"definitely not a certificate")
        with pytest.raises(ValueError, match="neither PEM nor DER"):
            load_certificate_file(path)


class TestRotationEndToEnd:
    """★ The scenario this module exists for.

    A card signed by the previous certificate must still verify after UIDAI
    rotates — because the store keeps both and the verifier tries each.
    """

    def test_card_verifies_against_older_certificate_in_a_rotated_store(
        self, tmp_path: Path
    ) -> None:
        signing_key = _new_key()

        cert_dir = tmp_path / "certs"
        cert_dir.mkdir()
        # The certificate that actually signed the card — nearer expiry.
        write_certificate(
            build_x509(signing_key, common_name="Previous UIDAI Key", valid_to_days=60),
            cert_dir / "previous.pem",
        )
        # The newly rotated-in certificate, unrelated key, further expiry.
        write_certificate(
            build_x509(_new_key(), common_name="Current UIDAI Key", valid_to_days=900),
            cert_dir / "current.pem",
        )

        store = FileCertificateStore(cert_dir)
        verifier = SecureQrVerifier(store.certificates())
        qr = SyntheticQrBuilder(private_key=signing_key).build()

        proof = verifier.verify(SecureQrParser().parse(qr))
        assert proof.valid is True, "rotation must not break existing cards"
        assert "Previous UIDAI Key" in (proof.certificate_subject or "")

    def test_single_certificate_store_breaks_on_rotation(self, tmp_path: Path) -> None:
        """The failure this design prevents — documented so nobody 'simplifies'
        the store back to a single certificate.
        """
        signing_key = _new_key()
        cert_dir = tmp_path / "certs"
        cert_dir.mkdir()
        write_certificate(
            build_x509(_new_key(), common_name="Only The New Key"), cert_dir / "current.pem"
        )

        verifier = SecureQrVerifier(FileCertificateStore(cert_dir).certificates())
        qr = SyntheticQrBuilder(private_key=signing_key).build()

        assert verifier.verify(SecureQrParser().parse(qr)).valid is False


class TestHealthReport:
    def test_summary_is_human_readable(self, tmp_path: Path) -> None:
        cert_dir, _ = make_cert_dir(tmp_path, count=2, valid_to_days=500)
        summary = FileCertificateStore(cert_dir).health().summary()
        assert "2 usable" in summary
        assert "pinning OFF" in summary

    def test_empty_store_summary_is_unambiguous(self, tmp_path: Path) -> None:
        cert_dir = tmp_path / "certs"
        cert_dir.mkdir()
        assert "TRUST STORE EMPTY" in FileCertificateStore(cert_dir).health().summary()

    def test_usable_certificates_excludes_expired(self, tmp_path: Path) -> None:
        cert_dir = tmp_path / "certs"
        cert_dir.mkdir()
        write_certificate(
            build_x509(_new_key(), valid_from_days=-800, valid_to_days=-1), cert_dir / "old.pem"
        )
        write_certificate(build_x509(_new_key(), valid_to_days=300), cert_dir / "new.pem")

        store = FileCertificateStore(cert_dir)
        assert len(store.certificates()) == 2
        assert len(store.usable_certificates()) == 1

    def test_store_satisfies_the_certificate_store_protocol(self, tmp_path: Path) -> None:
        cert_dir, _ = make_cert_dir(tmp_path, count=1)
        store = FileCertificateStore(cert_dir)
        assert isinstance(store.certificates(), list)
        assert isinstance(store.certificates()[0], UidaiCertificate)
        assert isinstance(store.days_to_earliest_expiry(), int)
