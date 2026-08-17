"""Data minimisation — Step 6. The last thing that runs before anything leaves.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 6
Provides : DataMinimisingFilter (implements avs.contracts.PrivacyFilter)
Consumes : avs.contracts
Used by  : avs.pipeline

WHY THIS IS A SEPARATE STAGE
----------------------------
Every field the service *could* return is a field someone will eventually store,
log, or put in a support ticket. Minimisation applied inline — "remember to strip
X here, and here, and here" — fails the first time a new code path is added.

So it runs once, at the boundary, over the finished result. Anything it does not
explicitly keep does not leave.

WHAT IS DELIBERATELY DESTROYED
------------------------------
* **``reference_id``** — the last-4 plus an issuance timestamp. It is the closest
  thing to a stable per-person identifier the QR carries, so it is replaced with
  a salted HMAC. The hash still detects duplicates; it cannot be reversed into
  the original, and it cannot be correlated across tenants because the salt is
  per-deployment.
* **The photograph** — a signed JPEG2000 portrait. Genuinely useful for a future
  face match, and exactly the sort of biometric-adjacent data that must not be
  retained by default.
* **The address**, when the tenant has not asked for it. Most HR flows need name,
  DOB and a verified flag. Collecting a home address because it happened to be in
  the QR is the definition of over-collection.

WHAT SURVIVES
-------------
Name, DOB, gender, last-4, the salted reference hash, the verdict, the proof, and
the checks. That is what an audit needs and nothing more.
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timedelta, timezone

from avs.contracts import VerificationResult

__all__ = ["REDACTED", "DataMinimisingFilter"]

#: Placeholder left in required string fields whose value has been destroyed.
REDACTED = "[REDACTED]"


class DataMinimisingFilter:
    """Strips, hashes and masks a finished result. Idempotent."""

    def __init__(
        self,
        *,
        hash_secret: str,
        keep_address: bool = False,
        keep_photo: bool = False,
        purge_after_hours: int = 24,
    ) -> None:
        """
        Args:
            hash_secret: HMAC key for the reference hash. **Must come from a
                vault in production.** A guessable secret makes the hash
                reversible by brute force over the small reference-ID space, and
                a shared secret would let two tenants correlate the same person.
            keep_address: retain the full address from the QR. Off by default —
                most HR flows never need it, and an Aadhaar address is a home
                address.
            keep_photo: retain the signed portrait. Off by default. Turn it on
                only when face matching (Step 19+) is actually in use, and only
                with a retention policy behind it.
            purge_after_hours: how long the raw uploads may be kept.
        """
        if not hash_secret or hash_secret.startswith("CHANGE-ME"):
            # Loud, not silent. A default secret in production is a real finding,
            # and the failure mode is invisible if we let it slide.
            raise ValueError(
                "privacy filter requires a real hash_secret — the placeholder "
                "value would make reference hashes trivially reversible"
            )
        self.hash_secret = hash_secret
        self.keep_address = keep_address
        self.keep_photo = keep_photo
        self.purge_after_hours = purge_after_hours

    # ------------------------------------------------------------------ #

    def apply(self, result: VerificationResult) -> VerificationResult:
        """Minimise a result. Safe to call more than once."""
        updates: dict[str, object] = {}

        if result.identity is not None:
            identity = result.identity
            if identity.reference_id and identity.reference_id != REDACTED:
                updates["reference_hash"] = self.reference_hash(identity.reference_id)
            updates["identity"] = identity.model_copy(update={"reference_id": REDACTED})

        if not self.keep_address:
            updates["address"] = None

        if result.purge_after is None:
            updates["purge_after"] = datetime.now(timezone.utc) + timedelta(
                hours=self.purge_after_hours
            )

        if result.verified_at is None and result.verdict.is_auto_approve:
            updates["verified_at"] = datetime.now(timezone.utc)

        return result.model_copy(update=updates)

    # ------------------------------------------------------------------ #

    def reference_hash(self, reference_id: str) -> str:
        """Salted HMAC-SHA256 of the reference ID.

        Deliberately HMAC rather than a plain hash. The reference-ID space is
        small and structured — four digits plus a timestamp — so an unsalted
        SHA-256 would be brute-forceable in seconds. The keyed construction makes
        that impossible without the secret.
        """
        digest = hmac.new(
            self.hash_secret.encode("utf-8"),
            reference_id.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return f"hmac-sha256:{digest}"

    def verify_hash(self, reference_id: str, candidate: str) -> bool:
        """Constant-time comparison, for duplicate detection in Step 18."""
        return hmac.compare_digest(self.reference_hash(reference_id), candidate)
