"""SSRF guard tests — Step 7.

⛔ THIS IS A SECURITY TEST FILE. A regression here hands the caller a
   server-side request forgery primitive: the ability to make the verification
   service issue HTTP requests to addresses only it can reach.

The realistic attack is one line of JSON:

    {"front_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}

On AWS, GCP and Azure that address returns instance credentials. The service
would fetch it, fail to find a QR, and — depending on how errors surface — leak
the response or confirm what is reachable inside the VPC.

The tests below pin the four properties that close it: scheme allow-list,
checking the RESOLVED ADDRESS rather than the hostname, refusing every private
range, and never following redirects.
"""

from __future__ import annotations

import asyncio
import socket

import pytest

from avs.storage import FetchError, SafeUrlFetcher, is_safe_url

# --------------------------------------------------------------------------- #
# Scheme allow-list
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "file:///c:/windows/system32/config/sam",
        "ftp://internal.example.com/secrets",
        "gopher://127.0.0.1:6379/_SET%20key%20value",
        "data:text/plain;base64,aGVsbG8=",
        "dict://127.0.0.1:11211/stat",
    ],
)
def test_only_http_schemes_are_allowed(url: str):
    """file:// reads local disk; gopher:// and dict:// can drive Redis/memcached."""
    check = is_safe_url(url)
    assert check.ok is False
    assert check.blocked is True


# --------------------------------------------------------------------------- #
# Address ranges
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://169.254.169.254/latest/meta-data/", "link-local"),  # ★ cloud metadata
        ("http://127.0.0.1:6379/", "loopback"),
        ("http://localhost:5432/", "loopback"),
        ("http://[::1]:8080/", "loopback"),
        ("http://10.0.0.5/internal", "private"),
        ("http://192.168.1.1/admin", "private"),
        ("http://172.16.0.10/", "private"),
        ("http://0.0.0.0/", "unspecified"),
    ],
)
def test_internal_addresses_are_refused(url: str, expected: str):
    check = is_safe_url(url)
    assert check.ok is False, f"{url} must be refused"
    assert check.blocked is True
    assert expected in check.reason


def test_public_address_is_allowed():
    check = is_safe_url("https://8.8.8.8/some-image.jpg")
    assert check.ok is True
    assert check.reason == ""


def test_hostname_resolving_to_loopback_is_refused(monkeypatch):
    """★ The check must run on the RESOLVED ADDRESS, not the hostname.

    An attacker controls their own DNS. `images.attacker.com` looks entirely
    ordinary and resolves to 127.0.0.1 — validating the name proves nothing.
    """

    def fake_getaddrinfo(host, port, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port or 80))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    check = is_safe_url("https://images.totally-legitimate-cdn.com/aadhaar.jpg")
    assert check.ok is False
    assert check.blocked is True
    assert "loopback" in check.reason


def test_any_forbidden_answer_refuses_the_whole_url(monkeypatch):
    """DNS can return several addresses and we do not choose which one is used.

    A record set mixing one public and one internal address must be refused —
    otherwise the outcome depends on which answer the HTTP client happens to
    pick, which is a coin flip an attacker can keep tossing.
    """

    def fake_getaddrinfo(host, port, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    assert is_safe_url("https://mixed-records.example.com/x.jpg").ok is False


# --------------------------------------------------------------------------- #
# blocked vs transient
# --------------------------------------------------------------------------- #


def test_dns_failure_is_transient_not_blocked(monkeypatch):
    """★ A resolver outage must stay retryable.

    Reporting it as a permanent refusal would fail every legitimate request for
    as long as DNS is unhealthy, and the caller would have no reason to retry.
    """

    def fake_getaddrinfo(host, port, **kwargs):
        raise socket.gaierror("Temporary failure in name resolution")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    check = is_safe_url("https://real-cdn.example.com/x.jpg")
    assert check.ok is False
    assert check.blocked is False, "DNS failure is transient, not a security refusal"


def test_forbidden_address_is_blocked_permanently():
    assert is_safe_url("http://127.0.0.1/x").blocked is True


# --------------------------------------------------------------------------- #
# Development escape hatch
# --------------------------------------------------------------------------- #


def test_allow_private_permits_localhost():
    """MinIO on localhost is the normal development setup."""
    assert is_safe_url("http://localhost:9000/bucket/front.jpg", allow_private=True).ok is True


def test_allow_private_still_refuses_non_http_schemes():
    """The dev flag relaxes address ranges — it must not open file:// as well."""
    check = is_safe_url("file:///etc/passwd", allow_private=True)
    assert check.ok is False
    assert check.blocked is True


# --------------------------------------------------------------------------- #
# Fetcher
# --------------------------------------------------------------------------- #


def test_fetch_refuses_before_making_any_request():
    """The refusal must happen before a socket is opened, not after.

    Driven with ``asyncio.run`` rather than pytest-asyncio: the assertion is
    about refusal, and adding an async test plugin to reach it would be dead
    weight in the one test file that must never be skipped for a missing dep.
    """
    with pytest.raises(FetchError) as exc:
        asyncio.run(SafeUrlFetcher().fetch("http://169.254.169.254/latest/meta-data/"))

    assert exc.value.blocked is True


def test_fetch_error_carries_the_blocked_flag():
    """Callers map blocked -> 400 and everything else -> retryable, so the flag
    has to be right or a security refusal looks like a transient glitch."""
    with pytest.raises(FetchError) as exc:
        asyncio.run(SafeUrlFetcher().fetch("file:///etc/passwd"))
    assert exc.value.blocked is True


def test_redirects_are_disabled_in_the_client():
    """A permitted URL that 302s to the metadata endpoint would defeat the
    address check, because the second request is never validated."""
    import inspect

    source = inspect.getsource(SafeUrlFetcher.fetch)
    assert "follow_redirects=False" in source
    assert "follow_redirects=True" not in source
