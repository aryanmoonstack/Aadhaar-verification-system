"""AVS — Aadhaar Verification Service.

A standalone service that verifies whether an uploaded Aadhaar card image is
genuine, by checking the UIDAI RSA-2048 signature embedded in its Secure QR code.

GOVERNING PRINCIPLE
-------------------
    AI makes the system smart. Cryptography makes it correct.

    AI operates on the INPUT side (classify, quality, localize, restore) and the
    HUMAN-ASSIST side (ocr, namematch, assist, support, anomaly).

    The VERDICT comes solely from avs.crypto.verify() — an RSA signature check.
    No model, heuristic, or threshold may produce an approval.

See CONTRACTS.md for the frozen interfaces and PROJECT_STATE.md for build status.
"""

__version__ = "0.1.0"
__contract_version__ = "1.9.0"

__all__ = ["__contract_version__", "__version__"]
