"""URL fetching with SSRF protection — Step 7.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 7 (Step 8 adds S3 credentials, streaming caps, retries)
Provides : SafeUrlFetcher, FetchError, is_safe_url()
Consumes : httpx
Used by  : avs.api
Status   : PARTIAL

⛔ WHY THIS MODULE IS SECURITY-CRITICAL

   The API accepts a ``source_url`` and fetches it. That is a **server-side
   request forgery primitive handed to the caller** unless it is constrained.

   A tenant — or anyone who compromises a tenant's credentials — could pass:

       http://169.254.169.254/latest/meta-data/iam/security-credentials/
           → cloud instance credentials on AWS/GCP/Azure
       http://localhost:6379/
           → the Redis instance the worker uses
       http://10.0.0.5/internal-admin
           → anything reachable inside the VPC
       file:///etc/passwd
           → local files, on some HTTP clients

   The service would dutifully fetch it and, depending on how errors surface,
   leak the contents or confirm existence. This is one of the most commonly
   exploited classes of bug in services that accept URLs.

   So: scheme allow-list, DNS resolution, and an IP check against every private,
   loopback, link-local and reserved range — performed on the **resolved
   address**, not the hostname, because ``evil.example.com`` can resolve to
   ``127.0.0.1``.

Redirects are disabled entirely. A permitted URL that 302s to the metadata
endpoint would defeat the check otherwise.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import NamedTuple
from urllib.parse import urlparse

import httpx

__all__ = ["FetchError", "SafeUrlFetcher", "UrlCheck", "is_safe_url"]


class UrlCheck(NamedTuple):
    """Outcome of a pre-fetch safety check.

    ``blocked`` separates "this URL is forbidden" from "we could not tell".
    A link-local address is forbidden forever and retrying is pointless. A DNS
    timeout is transient and the caller should try again — reporting both as
    the same non-retryable refusal would strand legitimate requests during a
    brief resolver outage.
    """

    ok: bool
    reason: str = ""
    blocked: bool = False


#: Only these schemes. No file://, no ftp://, no gopher://.
_ALLOWED_SCHEMES = frozenset({"https", "http"})


class FetchError(Exception):
    """Raised when a URL cannot be fetched, or must not be."""

    def __init__(self, message: str, *, blocked: bool = False) -> None:
        self.message = message
        self.blocked = blocked
        """True when refused for safety rather than failing to fetch."""
        super().__init__(message)


def _is_forbidden_address(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    """Return a reason when an address must not be fetched.

    Order matters for the MESSAGE, not the outcome — several of these overlap.
    ``0.0.0.0`` is unspecified *and* private; ``169.254.169.254`` is link-local
    *and* private. Most specific first, so the log line names the actual problem
    instead of the broadest category that happens to match.
    """
    if ip.is_unspecified:
        return "unspecified address"
    if ip.is_loopback:
        return "loopback address"
    if ip.is_link_local:
        # 169.254.0.0/16 — the cloud metadata endpoint lives here.
        return "link-local address (cloud metadata range)"
    if ip.is_private:
        return "private address"
    if ip.is_multicast:
        return "multicast address"
    if ip.is_reserved:
        return "reserved address"
    return None


def is_safe_url(url: str, *, allow_private: bool = False) -> UrlCheck:
    """Check a URL before fetching it.

    Args:
        allow_private: permit loopback and private addresses. **Local
            development only** — enabling this in production restores the SSRF
            hole this module exists to close.
    """
    try:
        parsed = urlparse(url)
    except ValueError as exc:
        return UrlCheck(False, f"malformed URL: {exc}", blocked=True)

    if parsed.scheme not in _ALLOWED_SCHEMES:
        return UrlCheck(False, f"scheme {parsed.scheme!r} is not allowed", blocked=True)
    if not parsed.hostname:
        return UrlCheck(False, "URL has no host", blocked=True)

    if allow_private:
        return UrlCheck(True)

    # Resolve, then check the ADDRESS — not the hostname. A hostname an attacker
    # controls can resolve to 127.0.0.1, so validating the name proves nothing.
    try:
        infos = socket.getaddrinfo(parsed.hostname, parsed.port or 0, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        # NOT blocked — a resolver outage is transient. Marking it permanent
        # would fail legitimate requests for the duration of a DNS blip.
        return UrlCheck(False, f"could not resolve host: {exc}", blocked=False)

    for info in infos:
        address = info[4][0]
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return UrlCheck(False, f"unparseable resolved address {address!r}", blocked=True)
        reason = _is_forbidden_address(ip)
        if reason is not None:
            # Every resolved address must be safe. One bad answer is enough to
            # refuse — DNS can return several, and we do not control which the
            # HTTP client picks.
            return UrlCheck(False, f"host resolves to a {reason}", blocked=True)

    return UrlCheck(True)


class SafeUrlFetcher:
    """Fetches bytes from a URL, refusing anything that could reach inside."""

    def __init__(
        self,
        *,
        max_bytes: int = 20 * 1024 * 1024,
        timeout_seconds: float = 15.0,
        allow_private: bool = False,
    ) -> None:
        """
        Args:
            max_bytes: hard cap. Enforced while streaming, so an endpoint that
                advertises 1 KB and then sends 10 GB is cut off rather than
                exhausting memory.
            allow_private: see ``is_safe_url``. Development only.
        """
        self.max_bytes = max_bytes
        self.timeout_seconds = timeout_seconds
        self.allow_private = allow_private

    async def fetch(self, url: str) -> bytes:
        """Fetch a URL. Raises ``FetchError`` on refusal or failure."""
        check = is_safe_url(url, allow_private=self.allow_private)
        if not check.ok:
            raise FetchError(f"refused to fetch URL: {check.reason}", blocked=check.blocked)

        try:
            # ⚠ Redirects OFF. A permitted URL that 302s to the metadata
            #   endpoint would otherwise walk straight past the check above.
            async with (
                httpx.AsyncClient(timeout=self.timeout_seconds, follow_redirects=False) as client,
                client.stream("GET", url) as response,
            ):
                if response.status_code in (301, 302, 303, 307, 308):
                    raise FetchError("redirects are not followed", blocked=True)
                if response.status_code >= 400:
                    raise FetchError(f"HTTP {response.status_code} fetching source")

                # Trust the declared length as a hint only — enforce the cap
                # against what actually arrives.
                chunks: list[bytes] = []
                total = 0
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    if total > self.max_bytes:
                        raise FetchError(f"source exceeded {self.max_bytes} bytes", blocked=True)
                    chunks.append(chunk)

        except httpx.HTTPError as exc:
            raise FetchError(f"could not fetch source: {exc}") from exc

        return b"".join(chunks)
