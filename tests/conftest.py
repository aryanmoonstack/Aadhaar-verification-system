"""Shared pytest fixtures.

⛔ PRIVACY RULE FOR THIS REPOSITORY
   No real Aadhaar image, QR payload string, or Aadhaar number may ever be
   committed. The corpus lives only on the developer's machine, at the path in
   AVS_CORPUS_DIR, and is git-ignored. Corpus-dependent tests are marked
   @pytest.mark.corpus and skip automatically when it is absent.

All fixtures below produce SYNTHETIC data — a throwaway RSA keypair generated
per session, and entirely fictional demographics.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from avs.crypto import SecureQrVerifier
from avs.parser import SecureQrParser
from avs.truststore import UidaiCertificate
from tests.fixtures.synthetic import SyntheticQrBuilder, make_test_keypair

# --------------------------------------------------------------------------- #
# Synthetic crypto fixtures — Step 1
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="session")
def _keypair() -> tuple[rsa.RSAPrivateKey, UidaiCertificate]:
    """RSA-2048 keypair standing in for UIDAI's signing key.

    Session-scoped: key generation is slow and the key is identical for every test.
    """
    return make_test_keypair()


@pytest.fixture(scope="session")
def test_key(_keypair: tuple[rsa.RSAPrivateKey, UidaiCertificate]) -> rsa.RSAPrivateKey:
    return _keypair[0]


@pytest.fixture(scope="session")
def test_certificate(
    _keypair: tuple[rsa.RSAPrivateKey, UidaiCertificate],
) -> UidaiCertificate:
    return _keypair[1]


@pytest.fixture
def builder(test_key: rsa.RSAPrivateKey) -> SyntheticQrBuilder:
    """Default synthetic payload builder — V2 layout, both hashes, compressed."""
    return SyntheticQrBuilder(private_key=test_key)


@pytest.fixture
def parser() -> SecureQrParser:
    return SecureQrParser()


@pytest.fixture
def verifier(test_certificate: UidaiCertificate) -> SecureQrVerifier:
    return SecureQrVerifier([test_certificate])


# --------------------------------------------------------------------------- #
# Local corpus — real cards, never committed, never sent anywhere
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="session")
def corpus_dir() -> Path:
    raw = os.environ.get("AVS_CORPUS_DIR")
    if not raw:
        pytest.skip("AVS_CORPUS_DIR not set — corpus tests skipped")
    path = Path(raw)
    if not path.exists():
        pytest.skip(f"corpus directory not found: {path}")
    return path


@pytest.fixture
def genuine_dir(corpus_dir: Path) -> Path:
    d = corpus_dir / "genuine"
    if not d.exists():
        pytest.skip("corpus/genuine not found")
    return d


@pytest.fixture
def tampered_dir(corpus_dir: Path) -> Path:
    d = corpus_dir / "tampered"
    if not d.exists():
        pytest.skip("corpus/tampered not found")
    return d
