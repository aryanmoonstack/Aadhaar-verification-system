"""Request authentication — Step 8.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 8
Provides : verify_request_signature(), sign_request(), SignatureCheck, NonceCache
Consumes : avs.config (tenant registry)
Used by  : avs.api
Status   : COMPLETE

⛔ UNTIL THIS EXISTED, ANYTHING THAT COULD REACH THE PORT COULD SUBMIT A
   DOCUMENT AND RECEIVE A VERDICT. Step 7 shipped with no authentication at all.

WHY HMAC AND NOT AN API KEY
---------------------------
A static API key is a bearer token: whoever holds it can replay any request
forever, and a key leaked in a log or a proxy trace stays usable until someone
notices. An HMAC signature covers the **timestamp, a nonce and the body**, so:

* a captured request cannot be replayed — the nonce is remembered and the
  timestamp expires;
* the body cannot be altered — a changed byte changes the signature;
* the secret itself never crosses the wire.

This is deliberately the same construction as the Step 7 callback dispatcher,
so the HRM implements one scheme in both directions rather than two.

THE THREE FAILURE MODES THIS GUARDS
-----------------------------------
**Replay.** Someone captures a valid verification request and re-sends it. The
nonce cache refuses the second one.

**Skew.** Clocks drift. A window too tight breaks legitimate callers, too loose
lets a captured request live for hours. Five minutes is the usual compromise
and is configurable.

**Timing.** Comparing signatures with ``==`` leaks how many leading bytes were
correct, which is enough to forge one byte at a time. ``compare_digest`` is
constant-time and is the only comparison used here.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
import time
import uuid
from dataclasses import dataclass

__all__ = [
    "MAX_CLOCK_SKEW_SECONDS",
    "NonceCache",
    "SignatureCheck",
    "SignatureHeaders",
    "build_signature",
    "sign_request",
    "verify_request_signature",
]

#: Header names. Shared verbatim with the Step 7 callback dispatcher.
HEADER_TENANT = "X-AVS-Tenant"
HEADER_SIGNATURE = "X-AVS-Signature"
HEADER_TIMESTAMP = "X-AVS-Timestamp"
HEADER_NONCE = "X-AVS-Nonce"

#: How far a caller's clock may drift. Five minutes: wide enough that ordinary
#: NTP drift never rejects a legitimate request, narrow enough that a captured
#: request is useless within one coffee break.
MAX_CLOCK_SKEW_SECONDS = 300


@dataclass(frozen=True, slots=True)
class SignatureCheck:
    """Outcome of authenticating one request.

    ``reason`` is for OUR logs. It is deliberately never returned to the caller:
    telling an attacker whether the tenant was unknown, the nonce was reused or
    the signature was wrong hands them a working oracle. The API answers every
    failure with the same opaque 401.
    """

    ok: bool
    tenant_id: str | None = None
    reason: str = ""


@dataclass(frozen=True, slots=True)
class SignatureHeaders:
    """Headers a caller must send. Returned by ``sign_request`` for clients."""

    tenant: str
    signature: str
    timestamp: str
    nonce: str

    def as_dict(self) -> dict[str, str]:
        return {
            HEADER_TENANT: self.tenant,
            HEADER_SIGNATURE: self.signature,
            HEADER_TIMESTAMP: self.timestamp,
            HEADER_NONCE: self.nonce,
        }


def build_signature(secret: str, timestamp: str, nonce: str, body: bytes) -> str:
    """The canonical string is ``timestamp.nonce.body``, HMAC-SHA256, hex.

    ⚠ The separator matters. Concatenating the parts without one allows a
      *canonicalisation collision*: ``("12", "3", b"x")`` and ``("1", "23",
      b"x")`` would otherwise hash identically, letting an attacker shift bytes
      between the timestamp and the nonce while keeping the signature valid.
      The dot is not decoration.
    """
    message = timestamp.encode("ascii") + b"." + nonce.encode("ascii") + b"." + body
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def sign_request(secret: str, tenant_id: str, body: bytes) -> SignatureHeaders:
    """Produce the headers for a request. Used by clients and by our own tests."""
    timestamp = str(int(time.time()))
    nonce = uuid.uuid4().hex
    return SignatureHeaders(
        tenant=tenant_id,
        signature=build_signature(secret, timestamp, nonce, body),
        timestamp=timestamp,
        nonce=nonce,
    )


class NonceCache:
    """Remembers recently seen nonces so a captured request cannot be replayed.

    Bounded by the same window as the clock-skew check: once a timestamp is too
    old to be accepted, its nonce can be forgotten, because the timestamp check
    alone now rejects it. That bound is what stops this becoming a memory leak
    in a long-running process.
    """

    def __init__(self, *, window_seconds: int = MAX_CLOCK_SKEW_SECONDS) -> None:
        self.window_seconds = window_seconds
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def check_and_remember(self, nonce: str) -> bool:
        """True if this nonce is new. False means a replay."""
        now = time.time()
        with self._lock:
            self._evict_locked(now)
            if nonce in self._seen:
                return False
            self._seen[nonce] = now
            return True

    def _evict_locked(self, now: float) -> None:
        cutoff = now - self.window_seconds
        stale = [nonce for nonce, seen in self._seen.items() if seen < cutoff]
        for nonce in stale:
            del self._seen[nonce]

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._seen)


def verify_request_signature(
    *,
    tenant_id: str | None,
    signature: str | None,
    timestamp: str | None,
    nonce: str | None,
    body: bytes,
    secret_for: object,
    nonce_cache: NonceCache,
    max_skew_seconds: int = MAX_CLOCK_SKEW_SECONDS,
    now: float | None = None,
) -> SignatureCheck:
    """Authenticate one request.

    Args:
        secret_for: callable taking a tenant id and returning its secret, or
            None when the tenant is unknown.

    The order of checks is deliberate: everything cheap and non-secret first, so
    a malformed or unauthenticated request never reaches the HMAC computation.
    """
    if not (tenant_id and signature and timestamp and nonce):
        return SignatureCheck(False, reason="missing authentication headers")

    try:
        sent_at = int(timestamp)
    except ValueError:
        return SignatureCheck(False, tenant_id, "timestamp is not an integer")

    current = time.time() if now is None else now
    drift = abs(current - sent_at)
    if drift > max_skew_seconds:
        return SignatureCheck(
            False, tenant_id, f"timestamp is {drift:.0f}s out, limit is {max_skew_seconds}s"
        )

    secret = secret_for(tenant_id)  # type: ignore[operator]
    if not secret:
        # ⚠ Still do everything below. Returning early on an unknown tenant
        #   makes the response measurably faster for unknown tenants than for
        #   known ones, which enumerates the tenant list. Compare against a
        #   dummy secret so the work is identical.
        secret = "\x00" * 32
        expected = build_signature(secret, timestamp, nonce, body)
        hmac.compare_digest(expected, signature)
        return SignatureCheck(False, tenant_id, "unknown tenant")

    expected = build_signature(secret, timestamp, nonce, body)
    if not hmac.compare_digest(expected, signature):
        return SignatureCheck(False, tenant_id, "signature mismatch")

    # ★ Replay check LAST. A valid signature is required before we are willing
    #   to spend memory remembering a nonce — otherwise anyone can fill the
    #   cache with garbage nonces and force eviction of real ones.
    if not nonce_cache.check_and_remember(nonce):
        return SignatureCheck(False, tenant_id, "nonce already used — replay")

    return SignatureCheck(True, tenant_id)
