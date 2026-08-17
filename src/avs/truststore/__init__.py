"""avs.truststore — UIDAI certificate trust store.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 1 (certificate model), Step 2 (directory store, pinning, health)
Provides : UidaiCertificate, FileCertificateStore, InMemoryCertificateStore,
           TrustStoreHealth, ExpiryStatus, LoadIssue, load_certificate_file,
           TrustStoreError
Consumes : avs.contracts, cryptography
Used by  : avs.crypto (Step 1), avs.health (Step 7), CLI
Status   : COMPLETE

TWO RULES THIS MODULE ENFORCES
------------------------------
1. **Rotation** — verification tries EVERY certificate in the store. A single
   hardcoded certificate silently breaks the service the day UIDAI rotates.

2. **Pinning** — when ``certs/FINGERPRINTS.txt`` is present, only certificates
   whose SHA-256 fingerprint is listed are loaded. Without it, write access to
   ``certs/`` is enough to mint approvals.
"""

from avs.truststore.certificate import (
    InMemoryCertificateStore,
    UidaiCertificate,
    load_certificate_file,
)
from avs.truststore.errors import TrustStoreError
from avs.truststore.store import (
    CERTIFICATE_SUFFIXES,
    PIN_FILE_NAME,
    ExpiryStatus,
    FileCertificateStore,
    LoadIssue,
    TrustStoreHealth,
)

__all__ = [
    "CERTIFICATE_SUFFIXES",
    "PIN_FILE_NAME",
    "ExpiryStatus",
    "FileCertificateStore",
    "InMemoryCertificateStore",
    "LoadIssue",
    "TrustStoreError",
    "TrustStoreHealth",
    "UidaiCertificate",
    "load_certificate_file",
]
