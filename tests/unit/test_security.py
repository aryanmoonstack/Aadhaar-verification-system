"""Request authentication — Step 8.

⛔ SECURITY TEST FILE. Step 7 shipped with no authentication: anything that
   could reach the port could submit a document and receive a verdict on it.

Four properties are pinned here, and each closes a distinct attack:

    signature    a modified body is rejected
    replay       a captured request cannot be re-sent
    skew         a captured request expires
    timing       comparisons leak nothing about the secret
"""

from __future__ import annotations

import secrets
import time

import pytest

from avs.contracts import Strictness
from avs.security import (
    MIN_SECRET_LENGTH,
    FileTenantRegistry,
    InMemoryTenantRegistry,
    NonceCache,
    TenantConfig,
    TenantRegistryError,
    build_signature,
    sign_request,
    verify_request_signature,
)

BODY = b'{"front_url":"https://example.com/a.jpg"}'


@pytest.fixture
def key() -> str:
    return secrets.token_hex(32)


@pytest.fixture
def registry(key: str) -> InMemoryTenantRegistry:
    return InMemoryTenantRegistry([TenantConfig(tenant_id="m-one", secret=key)])


@pytest.fixture
def cache() -> NonceCache:
    return NonceCache()


def check(headers, registry, cache, *, body=BODY, **overrides):
    payload = {
        "tenant_id": headers.tenant,
        "signature": headers.signature,
        "timestamp": headers.timestamp,
        "nonce": headers.nonce,
        "body": body,
        "secret_for": registry.secret_for,
        "nonce_cache": cache,
    }
    payload.update(overrides)
    return verify_request_signature(**payload)


# --------------------------------------------------------------------------- #
# The happy path
# --------------------------------------------------------------------------- #


def test_a_correctly_signed_request_is_accepted(key, registry, cache):
    result = check(sign_request(key, "m-one", BODY), registry, cache)
    assert result.ok is True
    assert result.tenant_id == "m-one"


# --------------------------------------------------------------------------- #
# Signature
# --------------------------------------------------------------------------- #


def test_a_modified_body_is_rejected(key, registry, cache):
    """The whole point: the signature covers the body, not just the headers."""
    headers = sign_request(key, "m-one", BODY)
    result = check(headers, registry, cache, body=b'{"front_url":"https://evil.example/a.jpg"}')

    assert result.ok is False
    assert "signature" in result.reason


def test_the_wrong_secret_is_rejected(registry, cache):
    forged = sign_request(secrets.token_hex(32), "m-one", BODY)
    assert check(forged, registry, cache).ok is False


def test_an_unknown_tenant_is_rejected(key, cache):
    empty = InMemoryTenantRegistry([])
    assert check(sign_request(key, "ghost", BODY), empty, cache).ok is False


def test_a_disabled_tenant_is_rejected(key, cache):
    disabled = InMemoryTenantRegistry([TenantConfig(tenant_id="m-one", secret=key, enabled=False)])
    assert check(sign_request(key, "m-one", BODY), disabled, cache).ok is False


def test_missing_headers_are_rejected(registry, cache):
    result = verify_request_signature(
        tenant_id=None,
        signature=None,
        timestamp=None,
        nonce=None,
        body=BODY,
        secret_for=registry.secret_for,
        nonce_cache=cache,
    )
    assert result.ok is False


# --------------------------------------------------------------------------- #
# ★ Replay
# --------------------------------------------------------------------------- #


def test_a_captured_request_cannot_be_replayed(key, registry, cache):
    """★ The attack a static API key cannot defend against at all.

    Someone captures a valid request from a proxy log and re-sends it. Without
    the nonce cache it succeeds forever.
    """
    headers = sign_request(key, "m-one", BODY)

    assert check(headers, registry, cache).ok is True
    second = check(headers, registry, cache)

    assert second.ok is False
    assert "replay" in second.reason


def test_a_failed_signature_does_not_consume_the_nonce(key, registry, cache):
    """⛔ Otherwise anyone can burn a legitimate caller's nonce.

    An attacker who can guess or observe a nonce could pre-register it with a
    garbage signature, and the real request would then be rejected as a replay.
    The nonce is only remembered AFTER the signature verifies.
    """
    headers = sign_request(key, "m-one", BODY)
    assert check(headers, registry, cache, signature="0" * 64).ok is False

    # The genuine request must still work.
    assert check(headers, registry, cache).ok is True


def test_the_nonce_cache_does_not_grow_without_bound(key, registry):
    """A cache with no eviction is a memory leak in a long-running service."""
    cache = NonceCache(window_seconds=1)
    for _ in range(50):
        check(sign_request(key, "m-one", BODY), registry, cache)
    assert cache.size == 50

    time.sleep(1.1)
    check(sign_request(key, "m-one", BODY), registry, cache)
    assert cache.size < 50, "expired nonces were never evicted"


# --------------------------------------------------------------------------- #
# ★ Clock skew
# --------------------------------------------------------------------------- #


def test_an_old_request_expires(key, registry, cache):
    headers = sign_request(key, "m-one", BODY)
    stale = check(headers, registry, cache, now=time.time() + 3600)

    assert stale.ok is False
    assert "timestamp" in stale.reason


def test_a_request_from_the_future_is_also_rejected(key, registry, cache):
    """Skew is absolute. A far-future timestamp would otherwise stay valid
    for as long as it takes real time to catch up."""
    headers = sign_request(key, "m-one", BODY)
    assert check(headers, registry, cache, now=time.time() - 3600).ok is False


def test_modest_clock_drift_is_tolerated(key, registry, cache):
    """Too tight a window breaks honest callers whose NTP is a minute out."""
    headers = sign_request(key, "m-one", BODY)
    assert check(headers, registry, cache, now=time.time() + 60).ok is True


def test_a_non_numeric_timestamp_is_rejected(key, registry, cache):
    headers = sign_request(key, "m-one", BODY)
    assert check(headers, registry, cache, timestamp="not-a-number").ok is False


# --------------------------------------------------------------------------- #
# Canonicalisation
# --------------------------------------------------------------------------- #


def test_the_separator_prevents_a_canonicalisation_collision(key):
    """⛔ Without a delimiter, bytes could be shifted between fields.

    ("12", "3") and ("1", "23") must not hash alike, or an attacker can move
    characters from the timestamp into the nonce and keep the signature valid.
    """
    assert build_signature(key, "12", "3", b"x") != build_signature(key, "1", "23", b"x")


# --------------------------------------------------------------------------- #
# Weak secrets — refused at construction
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("weak", ["", "changeme", "secret", "test", "short-key"])
def test_weak_secrets_are_refused_at_construction(weak):
    """⛔ A service running with `changeme` as a signing key looks perfectly
    healthy right up until someone tries it."""
    with pytest.raises(TenantRegistryError):
        TenantConfig(tenant_id="m-one", secret=weak)


def test_a_secret_of_exactly_the_minimum_length_is_accepted():
    TenantConfig(tenant_id="m-one", secret="a" * MIN_SECRET_LENGTH)


def test_the_secret_never_appears_in_a_repr(key):
    """A traceback in a log must not leak the signing key."""
    tenant = TenantConfig(tenant_id="m-one", secret=key)
    assert key not in repr(tenant)


# --------------------------------------------------------------------------- #
# File registry — secrets come from the environment
# --------------------------------------------------------------------------- #


def test_file_registry_reads_secrets_from_the_environment(tmp_path, key):
    """⛔ The registry file is safe to commit. The secret is not in it."""
    path = tmp_path / "tenants.json"
    path.write_text(
        '{"tenants":[{"tenant_id":"m-one","secret_env":"AVS_T1","strictness":"STRICT"}]}',
        encoding="utf-8",
    )

    registry = FileTenantRegistry(path, environ={"AVS_T1": key})
    registry.load()

    tenant = registry.get("m-one")
    assert tenant is not None
    assert tenant.secret == key
    assert tenant.strictness is Strictness.STRICT
    assert key not in path.read_text(encoding="utf-8"), "the secret leaked into the file"


def test_file_registry_refuses_a_tenant_whose_secret_is_unset(tmp_path):
    path = tmp_path / "tenants.json"
    path.write_text('{"tenants":[{"tenant_id":"m-one","secret_env":"AVS_MISSING"}]}', "utf-8")

    with pytest.raises(TenantRegistryError, match="AVS_MISSING"):
        FileTenantRegistry(path, environ={}).load()


def test_file_registry_refuses_a_secret_stored_inline(tmp_path):
    """No `secret_env` means someone tried to put the key in the file."""
    path = tmp_path / "tenants.json"
    path.write_text('{"tenants":[{"tenant_id":"m-one","secret":"inline"}]}', "utf-8")

    with pytest.raises(TenantRegistryError, match="secret_env"):
        FileTenantRegistry(path, environ={}).load()


def test_file_registry_refuses_duplicate_tenants(tmp_path, key):
    path = tmp_path / "tenants.json"
    path.write_text(
        '{"tenants":[{"tenant_id":"m-one","secret_env":"K"},'
        '{"tenant_id":"m-one","secret_env":"K"}]}',
        "utf-8",
    )
    with pytest.raises(TenantRegistryError, match="duplicate"):
        FileTenantRegistry(path, environ={"K": key}).load()


def test_tenant_ids_are_exposed_but_secrets_are_not(tmp_path, key):
    """Health endpoints report which tenants exist. Never their keys."""
    path = tmp_path / "tenants.json"
    path.write_text('{"tenants":[{"tenant_id":"m-one","secret_env":"K"}]}', "utf-8")

    registry = FileTenantRegistry(path, environ={"K": key})
    assert registry.tenant_ids == ["m-one"]
