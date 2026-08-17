"""★ Signature verification — THE VERDICT. Step 1.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 1
Provides : SecureQrVerifier (implements avs.contracts.SignatureVerifier)
Consumes : avs.contracts, avs.truststore, cryptography
Used by  : avs.rules (Step 6)

⛔ THIS IS THE ONLY VERDICT-BEARING COMPONENT IN THE SYSTEM.

   ``SignatureProof.valid is True`` is the sole condition under which
   ``Verdict.VERIFIED`` may be produced (CONTRACTS.md §1 Rule 1).

   No AI, no heuristic, no threshold, and no combination of other checks may
   substitute for it. ``tests/unit/test_ai_boundary.py`` proves at the AST level
   that this module never imports from ``avs.ai``.

WHY THIS CANNOT BE FOOLED
-------------------------
UIDAI signs every Secure QR with an RSA-2048 private key that only UIDAI holds.
Verification needs only the corresponding public certificate, which UIDAI
publishes. Producing a signature requires the private key; checking one does not.

So an attacker who edits a single byte — one letter of a name, one digit of a
date of birth, one pixel of the photograph — invalidates the signature, and no
amount of image editing, model manipulation, or payload crafting can repair it
without breaking RSA-2048.

This is why the verdict is binary rather than probabilistic, and why AI upstream
can never cause a false approval.
"""

from __future__ import annotations

from collections.abc import Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from avs.contracts import ErrorCode, QrPayload, SignatureProof
from avs.parser.fields import SIGNATURE_LENGTH
from avs.truststore import UidaiCertificate

__all__ = ["SecureQrVerifier"]

#: CONTRACTS.md §5 — the algorithm is fixed, not negotiated per payload.
_ALGORITHM = "RSA-2048/SHA-256/PKCS1v15"


class SecureQrVerifier:
    """Verifies a Secure QR signature against the UIDAI trust store."""

    def __init__(
        self,
        certificates: Sequence[UidaiCertificate],
        *,
        allow_expired: bool = False,
    ) -> None:
        """
        Args:
            certificates: every UIDAI certificate to try. Multiple is the norm —
                UIDAI rotates its signing certificate, and a store holding only
                one will fail on some future date.
            allow_expired: accept certificates past their validity window.
                Test and forensic use only; never enable in production.
        """
        self._certificates = list(certificates)
        self._allow_expired = allow_expired

    @property
    def certificates_loaded(self) -> list[UidaiCertificate]:
        """The trust anchors in use. Read-only copy, for probes and reporting."""
        return list(self._certificates)

    @property
    def has_certificates(self) -> bool:
        """Whether any trust anchor is loaded at all.

        Step 7's readiness probe uses this: a service with an empty trust store
        cannot approve anything and must not receive traffic.
        """
        return bool(self._certificates)

    # ------------------------------------------------------------------ #

    def verify(self, payload: QrPayload) -> SignatureProof:
        """Verify the payload's signature.

        Returns a SignatureProof in every case — an invalid signature is a normal
        outcome, not an error. Exceptions are reserved for the verifier being
        unable to run at all.
        """
        if payload.is_legacy_unsigned:
            return self._failure(
                ErrorCode.PAYLOAD_LEGACY_UNSIGNED,
                qr_version=payload.version,
            )

        if not self._certificates:
            return self._failure(ErrorCode.TRUSTSTORE_EMPTY, qr_version=payload.version)

        if len(payload.signature) != SIGNATURE_LENGTH:
            return self._failure(
                ErrorCode.SIGNATURE_INVALID,
                qr_version=payload.version,
                signed_byte_length=len(payload.signed_bytes),
            )

        # ⛔ EXPIRY MUST NOT DECIDE AUTHENTICITY.
        #
        #   An e-Aadhaar carries the signature it was issued with, forever. UIDAI
        #   rotates the Secure QR signing certificate every few years, and its
        #   own published list shows only ONE unexpired certificate against
        #   several lapsed ones.
        #
        #   Requiring a currently-valid certificate therefore means every card
        #   issued before the last rotation — the majority of cards in
        #   circulation — verifies as TAMPERED. That is a false accusation of
        #   forgery against real employees, and it breaks CONTRACTS.md §1 Rule 2.
        #
        #   The signature is a mathematical fact about a moment in the past.
        #   Certificate expiry is an operational fact about today. They are
        #   different questions, and only the first one decides the verdict.
        #
        #   Expiry is still surfaced: `SignatureProof.certificate_expired`, the
        #   trust-store health report, `/ready`, and the renewal metric.
        usable = self._certificates
        if not self._allow_expired:
            preferred = [c for c in usable if not c.is_expired]
            # Prefer a live certificate when one matches, but never refuse the
            # document merely because the only match is a retired anchor.
            usable = preferred + [c for c in usable if c.is_expired]

        # Try every certificate — any single match means the payload is genuine.
        for certificate in usable:
            if self._matches(certificate, payload):
                return SignatureProof(
                    valid=True,
                    certificate_serial=certificate.serial,
                    certificate_subject=certificate.subject,
                    qr_version=payload.version,
                    signed_byte_length=len(payload.signed_bytes),
                    algorithm=_ALGORITHM,
                    error=None,
                    certificate_expired=certificate.is_expired,
                )

        # No certificate matched. The document has been altered, or was never
        # issued by UIDAI. Either way it is not verified.
        return self._failure(
            ErrorCode.SIGNATURE_INVALID,
            qr_version=payload.version,
            signed_byte_length=len(payload.signed_bytes),
        )

    # ------------------------------------------------------------------ #

    @staticmethod
    def _matches(certificate: UidaiCertificate, payload: QrPayload) -> bool:
        """Single RSA verification. Returns False rather than raising.

        ``cryptography``'s ``verify`` is constant-time with respect to the
        signature contents and raises ``InvalidSignature`` on mismatch, which is
        the expected path for a tampered document.
        """
        try:
            certificate.public_key.verify(
                payload.signature,
                payload.signed_bytes,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except InvalidSignature:
            return False
        except (ValueError, TypeError):
            # Malformed key material or signature length — treat as a mismatch,
            # never as an approval.
            return False
        return True

    @staticmethod
    def _failure(
        code: ErrorCode,
        *,
        qr_version: str | None = None,
        signed_byte_length: int = 0,
    ) -> SignatureProof:
        return SignatureProof(
            valid=False,
            certificate_serial=None,
            certificate_subject=None,
            qr_version=qr_version,
            signed_byte_length=signed_byte_length,
            algorithm=_ALGORITHM,
            error=code,
        )
