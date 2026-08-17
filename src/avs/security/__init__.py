"""avs.security — request authentication and tenant identity.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 8
Provides : HMAC request authentication, per-tenant configuration
Consumes : avs.contracts
Used by  : avs.api
Status   : COMPLETE

⛔ STEP 7 SHIPPED WITH NO AUTHENTICATION. Anything that could reach the port
   could submit a document and receive a verdict on it. This module closes that.

Two pieces:

* ``signing`` — HMAC-SHA256 over ``timestamp.nonce.body``, with replay and
  clock-skew protection. Deliberately the same construction as the Step 7
  callback dispatcher, so the HRM implements one scheme in both directions.
* ``tenants`` — who is allowed to call, with what policy, using which key.
  Secrets are read from the environment; the registry file holds only the
  NAME of the variable and is safe to commit.
"""

from avs.security.signing import (
    HEADER_NONCE,
    HEADER_SIGNATURE,
    HEADER_TENANT,
    HEADER_TIMESTAMP,
    MAX_CLOCK_SKEW_SECONDS,
    NonceCache,
    SignatureCheck,
    SignatureHeaders,
    build_signature,
    sign_request,
    verify_request_signature,
)
from avs.security.tenants import (
    MIN_SECRET_LENGTH,
    FileTenantRegistry,
    InMemoryTenantRegistry,
    TenantConfig,
    TenantRegistry,
    TenantRegistryError,
)

__all__ = [
    "HEADER_NONCE",
    "HEADER_SIGNATURE",
    "HEADER_TENANT",
    "HEADER_TIMESTAMP",
    "MAX_CLOCK_SKEW_SECONDS",
    "MIN_SECRET_LENGTH",
    "FileTenantRegistry",
    "InMemoryTenantRegistry",
    "NonceCache",
    "SignatureCheck",
    "SignatureHeaders",
    "TenantConfig",
    "TenantRegistry",
    "TenantRegistryError",
    "build_signature",
    "sign_request",
    "verify_request_signature",
]
