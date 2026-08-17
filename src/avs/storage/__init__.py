"""avs.storage — fetching source images.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 7 (Step 8 adds S3 credentials, retries, tenant-scoped keys)
Provides : SafeUrlFetcher, FetchError, is_safe_url()
Consumes : httpx
Used by  : avs.api
Status   : PARTIAL

⛔ SSRF PROTECTION LIVES HERE. Accepting a URL and fetching it hands the caller a
   server-side request primitive. Every fetch resolves the host and refuses
   loopback, private, link-local (cloud metadata) and reserved addresses —
   checked against the RESOLVED ADDRESS, since a hostname an attacker controls
   can resolve to 127.0.0.1. Redirects are disabled for the same reason.
"""

from avs.storage.fetcher import FetchError, SafeUrlFetcher, is_safe_url

__all__ = ["FetchError", "SafeUrlFetcher", "is_safe_url"]
