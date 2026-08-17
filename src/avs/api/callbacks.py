"""Callback dispatch — Step 7.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 7
Provides : CallbackDispatcher
Consumes : httpx, avs.contracts
Used by  : avs.api

⛔ CALLBACKS ARE SIGNED.

   The HRM must be able to tell a genuine result from something an attacker
   POSTed to its callback endpoint. Without a signature, anyone who learns the
   callback URL can assert "employee X is VERIFIED" — which would let them
   approve their own forged document by skipping the service entirely.

   So every callback carries an HMAC-SHA256 over the raw body plus a timestamp
   and a nonce. Spring validates all three: signature, freshness, and that the
   nonce has not been seen (replay).

Delivery is best-effort with bounded retries. A callback that cannot be delivered
is logged, not retried forever — the caller can always poll ``GET /v1/verify/{id}``,
which is why that route exists.
"""

from __future__ import annotations

import hashlib
import hmac
import time
import uuid

import httpx

from avs.contracts import VerificationResult
from avs.logging import get_logger

__all__ = ["CallbackDispatcher"]

log = get_logger(__name__)


class CallbackDispatcher:
    """Delivers a finished result to the HRM, signed."""

    def __init__(
        self,
        *,
        secret: str = "",
        timeout_seconds: float = 10.0,
        max_attempts: int = 3,
    ) -> None:
        self.secret = secret
        self.timeout_seconds = timeout_seconds
        self.max_attempts = max_attempts

    def sign(self, body: bytes, timestamp: str, nonce: str) -> str:
        """HMAC-SHA256 over timestamp.nonce.body.

        The timestamp and nonce are inside the signed material, not merely sent
        alongside it — otherwise an attacker could replay a captured body with a
        fresh timestamp and it would still validate.
        """
        message = b".".join([timestamp.encode(), nonce.encode(), body])
        return hmac.new(self.secret.encode(), message, hashlib.sha256).hexdigest()

    def send(self, url: str, result: VerificationResult) -> bool:
        """Deliver a result. Returns True on success. Never raises."""
        body = result.model_dump_json().encode("utf-8")
        timestamp = str(int(time.time()))
        nonce = uuid.uuid4().hex

        headers = {
            "Content-Type": "application/json",
            "X-AVS-Timestamp": timestamp,
            "X-AVS-Nonce": nonce,
        }
        if self.secret:
            headers["X-AVS-Signature"] = self.sign(body, timestamp, nonce)
        else:
            log.warning("callback_unsigned", job_id=result.job_id)

        for attempt in range(1, self.max_attempts + 1):
            try:
                response = httpx.post(
                    url, content=body, headers=headers, timeout=self.timeout_seconds
                )
                if response.status_code < 400:
                    return True
                log.warning(
                    "callback_rejected",
                    job_id=result.job_id,
                    status=response.status_code,
                    attempt=attempt,
                )
            except httpx.HTTPError as exc:
                log.warning(
                    "callback_failed", job_id=result.job_id, attempt=attempt, error=str(exc)
                )

            if attempt < self.max_attempts:
                time.sleep(min(2**attempt, 8))

        # Give up. The caller can still poll — that route exists precisely so a
        # callback failure is an inconvenience rather than a lost verification.
        log.error("callback_abandoned", job_id=result.job_id, attempts=self.max_attempts)
        return False
