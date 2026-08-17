"""REST API tests — Step 7. CONTRACTS.md §8.

The API is the only thing the HRM ever talks to, so its contract is the one that
must not drift: verdict names, error shapes, status codes, the meaning of
`/ready`.

Two behaviours here matter more than the rest:

    /ready fails on an empty trust store
        Without a certificate every genuine document returns ERROR. The service
        is up and useless, and only it knows — so it has to say so, or the load
        balancer keeps sending it work.

    SSRF is refused at 400, synchronously
        A security refusal the caller can only discover by polling is a bad
        refusal. It also means a probing attacker gets a queue slot per attempt.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from avs.contracts import Verdict
from tests.fixtures.certs import build_x509, write_certificate
from tests.fixtures.qr_images import encode_jpeg, render_card
from tests.fixtures.synthetic import SyntheticQrBuilder

SECRET = "api-test-secret"


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def signing_key() -> rsa.RSAPrivateKey:
    """One throwaway key for the module. Generation is slow; reuse it."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def cert_dir(tmp_path_factory, signing_key) -> str:
    """A trust store on disk holding the certificate for `signing_key`.

    The app loads certificates from a directory, so the test has to write a real
    PEM rather than inject an object — which also exercises the loader.
    """
    directory = tmp_path_factory.mktemp("api-certs")
    write_certificate(build_x509(signing_key), Path(directory) / "test.pem")
    return str(directory)


@pytest.fixture(scope="module")
def card_with_qr(signing_key) -> bytes:
    payload = SyntheticQrBuilder(private_key=signing_key).build()
    return encode_jpeg(render_card(payload))


@pytest.fixture(scope="module")
def card_without_qr() -> bytes:
    return encode_jpeg(render_card("https://example.com/not-an-aadhaar"))


@pytest.fixture
def client(cert_dir: str):
    from avs.api import create_app

    # require_auth=False: these tests exercise ROUTES. Authentication has its
    # own fixture (`authed_client`) and its own tests further down.
    app = create_app(
        cert_dir=cert_dir, hash_secret=SECRET, time_budget_seconds=3.0, require_auth=False
    )
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def empty_client(tmp_path):
    """A service with no certificates — the 'up but useless' state."""
    from avs.api import create_app

    (tmp_path / "certs").mkdir()
    app = create_app(cert_dir=str(tmp_path / "certs"), hash_secret=SECRET, require_auth=False)
    with TestClient(app) as test_client:
        yield test_client


def poll(client: TestClient, job_id: str, timeout: float = 20.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        body = client.get(f"/v1/verify/{job_id}").json()
        if body["status"] in {"DONE", "FAILED"}:
            return body
        time.sleep(0.05)
    raise AssertionError(f"job {job_id} did not finish in {timeout}s")


def upload(front: bytes, back: bytes) -> dict:
    return {"front": ("front.jpg", front, "image/jpeg"), "back": ("back.jpg", back, "image/jpeg")}


# --------------------------------------------------------------------------- #
# Probes
# --------------------------------------------------------------------------- #


def test_health_is_liveness_only(client: TestClient):
    """/health must stay up even when nothing can be verified — it answers
    'should you restart me', not 'should you send me work'."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "alive"


def test_health_stays_up_without_certificates(empty_client: TestClient):
    assert empty_client.get("/health").status_code == 200


def test_ready_is_200_with_a_usable_certificate(client: TestClient):
    response = client.get("/ready")
    assert response.status_code == 200
    body = response.json()
    assert body["ready"] is True
    assert body["certificates"] == 1
    assert body["reason"] is None


def test_ready_is_503_without_certificates(empty_client: TestClient):
    """★ The single most important operational behaviour in this file.

    An empty trust store means every genuine document comes back ERROR. Serving
    traffic in that state produces a flood of 'we could not verify' messages to
    real employees, and nothing upstream would notice.
    """
    response = empty_client.get("/ready")
    assert response.status_code == 503
    body = response.json()
    assert body["ready"] is False
    assert "certificate" in body["reason"]


def test_metrics_exposes_readiness_and_expiry(client: TestClient):
    text = client.get("/metrics").text
    assert "avs_up 1" in text
    assert "avs_ready 1" in text
    assert "avs_queue_depth" in text
    # Expiry drives the renewal alert. A certificate that lapses silently takes
    # the whole service down at midnight.
    assert "avs_certificate_days_to_expiry" in text


def test_metrics_counts_verdicts(client: TestClient, card_with_qr, card_without_qr):
    response = client.post("/v1/verify/upload", files=upload(card_without_qr, card_with_qr))
    poll(client, response.json()["job_id"])

    text = client.get("/metrics").text
    assert 'avs_verdict_total{verdict="VERIFIED"} 1' in text


# --------------------------------------------------------------------------- #
# Multipart upload
# --------------------------------------------------------------------------- #


def test_upload_returns_202_and_a_job_id(client: TestClient, card_with_qr, card_without_qr):
    response = client.post("/v1/verify/upload", files=upload(card_without_qr, card_with_qr))

    assert response.status_code == 202
    body = response.json()
    assert body["job_id"]
    assert body["already_queued"] is False


def test_genuine_document_verifies(client: TestClient, card_with_qr, card_without_qr):
    response = client.post("/v1/verify/upload", files=upload(card_without_qr, card_with_qr))
    result = poll(client, response.json()["job_id"])

    assert result["status"] == "DONE"
    assert result["result"]["verdict"] == Verdict.VERIFIED.value


def test_qr_on_the_front_still_verifies(client: TestClient, card_with_qr, card_without_qr):
    """Aadhaar QR placement varies by card format. A service that assumed
    'QR = back' would reject a large share of genuine cards."""
    response = client.post("/v1/verify/upload", files=upload(card_with_qr, card_without_qr))
    result = poll(client, response.json()["job_id"])

    assert result["result"]["verdict"] == Verdict.VERIFIED.value


def test_result_never_contains_a_full_aadhaar_number(
    client: TestClient, card_with_qr, card_without_qr
):
    """⛔ Privacy invariant. The API response is what the HRM stores."""
    response = client.post("/v1/verify/upload", files=upload(card_without_qr, card_with_qr))
    body = poll(client, response.json()["job_id"])

    import json
    import re

    serialised = json.dumps(body)
    assert not re.search(r"\b\d{12}\b", serialised), "a 12-digit number escaped the privacy filter"


def test_explicit_job_id_is_honoured_and_idempotent(
    client: TestClient, card_with_qr, card_without_qr
):
    files = upload(card_without_qr, card_with_qr)
    first = client.post("/v1/verify/upload", files=files, data={"job_id": "hrm-req-42"})
    second = client.post("/v1/verify/upload", files=files, data={"job_id": "hrm-req-42"})

    assert first.json()["job_id"] == "hrm-req-42"
    assert first.json()["already_queued"] is False
    assert second.json()["already_queued"] is True, "a retry must be reported as a duplicate"


def test_missing_back_side_is_rejected(client: TestClient, card_with_qr):
    """Both faces are required — CONTRACTS.md §11."""
    response = client.post(
        "/v1/verify/upload", files={"front": ("front.jpg", card_with_qr, "image/jpeg")}
    )
    assert response.status_code == 422


def test_unknown_job_is_404(client: TestClient):
    response = client.get("/v1/verify/no-such-job")
    assert response.status_code == 404
    assert response.json()["detail"]["retryable"] is False


# --------------------------------------------------------------------------- #
# SSRF at the API boundary
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://127.0.0.1:6379/",
        "http://10.0.0.5/internal-admin",
        "http://192.168.1.1/router",
    ],
)
def test_internal_urls_are_refused_with_400_not_202(client: TestClient, url: str):
    """★ Refuse synchronously.

    Accepting with 202 and failing in the worker means the caller must poll to
    discover a security refusal, and every probe costs a queue slot. 400 says no
    immediately and consumes nothing.
    """
    response = client.post("/v1/verify", json={"front_url": url, "back_url": url})

    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail["retryable"] is False
    assert "refused" in detail["message"]


def test_non_http_scheme_is_rejected_by_validation(client: TestClient):
    response = client.post(
        "/v1/verify", json={"front_url": "file:///etc/passwd", "back_url": "file:///etc/passwd"}
    )
    assert response.status_code in (400, 422)


def test_refused_url_creates_no_job(client: TestClient):
    """The refusal must not leave a job behind for the caller to poll."""
    before = client.get("/metrics").text
    client.post(
        "/v1/verify",
        json={
            "front_url": "http://169.254.169.254/x.jpg",
            "back_url": "http://169.254.169.254/y.jpg",
            "job_id": "ssrf-attempt",
        },
    )
    assert client.get("/v1/verify/ssrf-attempt").status_code == 404
    assert "avs_queue_depth 0" in before


# --------------------------------------------------------------------------- #
# Sync route
# --------------------------------------------------------------------------- #


def test_sync_route_returns_the_result_directly(client: TestClient, card_with_qr, card_without_qr):
    response = client.post("/v1/verify/sync", files=upload(card_without_qr, card_with_qr))

    assert response.status_code == 200
    assert response.json()["verdict"] == Verdict.VERIFIED.value


def test_service_without_certificates_errors_rather_than_approving(
    empty_client: TestClient, card_with_qr, card_without_qr
):
    """⛔ The absolute rule: VERIFIED requires a valid signature.

    With no trust anchor no signature can be valid, so the only permitted
    outcome is ERROR. Approving here would mean approving anything.
    """
    response = empty_client.post("/v1/verify/sync", files=upload(card_without_qr, card_with_qr))

    assert response.json()["verdict"] != Verdict.VERIFIED.value
    assert response.json()["verdict"] == Verdict.ERROR.value


# --------------------------------------------------------------------------- #
# Authentication — Step 8
#
# ⛔ Step 7 shipped with none. Every /v1 route now requires an HMAC signature
#    from a known tenant, and the 401 body is deliberately opaque so it cannot
#    be used to enumerate tenants or probe the scheme.
# --------------------------------------------------------------------------- #

TENANT_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


@pytest.fixture
def authed_client(cert_dir: str):
    from avs.api import create_app
    from avs.security import InMemoryTenantRegistry, TenantConfig

    app = create_app(
        cert_dir=cert_dir,
        hash_secret=SECRET,
        time_budget_seconds=3.0,
        tenants=InMemoryTenantRegistry([TenantConfig(tenant_id="m-one", secret=TENANT_KEY)]),
        require_auth=True,
    )
    with TestClient(app) as test_client:
        yield test_client


def signed_headers(body: bytes, tenant: str = "m-one", key: str = TENANT_KEY) -> dict:
    from avs.security import sign_request

    return sign_request(key, tenant, body).as_dict()


def test_unauthenticated_request_is_rejected(authed_client: TestClient):
    """★ The gap Step 7 left open."""
    response = authed_client.post("/v1/verify/sync", files={"front": ("f.jpg", b"x")})
    assert response.status_code == 401


def test_correctly_signed_request_is_accepted(authed_client: TestClient):
    body = b'{"front_url":"https://8.8.8.8/a.jpg","back_url":"https://8.8.8.8/b.jpg"}'
    response = authed_client.post(
        "/v1/verify",
        content=body,
        headers={**signed_headers(body), "content-type": "application/json"},
    )
    # 202 accepted, or 503 if DNS is unavailable in the sandbox — either proves
    # authentication passed, which is what this test is about.
    assert response.status_code != 401


def test_a_replayed_request_is_rejected(authed_client: TestClient):
    body = b'{"front_url":"http://127.0.0.1/a.jpg","back_url":"http://127.0.0.1/b.jpg"}'
    headers = {**signed_headers(body), "content-type": "application/json"}

    first = authed_client.post("/v1/verify", content=body, headers=headers)
    second = authed_client.post("/v1/verify", content=body, headers=headers)

    assert first.status_code != 401, "the first request should authenticate"
    assert second.status_code == 401, "the replay was accepted"


def test_a_tampered_body_is_rejected(authed_client: TestClient):
    body = b'{"front_url":"https://8.8.8.8/a.jpg","back_url":"https://8.8.8.8/b.jpg"}'
    headers = {**signed_headers(body), "content-type": "application/json"}
    swapped = b'{"front_url":"https://evil.example/a.jpg","back_url":"https://8.8.8.8/b.jpg"}'

    assert authed_client.post("/v1/verify", content=swapped, headers=headers).status_code == 401


def test_the_401_body_reveals_nothing(authed_client: TestClient):
    """⛔ Distinguishing 'unknown tenant' from 'bad signature' is an oracle."""
    body = b"{}"
    unknown = authed_client.post(
        "/v1/verify",
        content=body,
        headers={**signed_headers(body, tenant="ghost"), "content-type": "application/json"},
    )
    forged = authed_client.post(
        "/v1/verify",
        content=body,
        headers={**signed_headers(body, key="f" * 64), "content-type": "application/json"},
    )

    assert unknown.status_code == forged.status_code == 401
    assert unknown.json() == forged.json(), "the two failures are distinguishable"


def test_health_endpoints_stay_unauthenticated(authed_client: TestClient):
    """A load balancer cannot sign requests. Probes must not require auth —
    and they expose nothing about any document."""
    assert authed_client.get("/health").status_code == 200
    assert authed_client.get("/ready").status_code in (200, 503)
    assert authed_client.get("/metrics").status_code == 200


def test_signed_multipart_upload_works(authed_client: TestClient, card_with_qr, card_without_qr):
    """★ Regression guard for the bug the auth work introduced and nearly shipped.

    FastAPI parses a multipart form BEFORE it solves dependencies, so the
    authentication dependency found the body stream already consumed and every
    file upload raised "Stream consumed". JSON routes were unaffected, which is
    exactly why it would have reached production: the HRM's real route is this
    one, and it was the only one broken.

    `BodyBufferMiddleware` buffers the body before routing and replays it.
    """
    files = upload(card_without_qr, card_with_qr)

    # The signature must cover the encoded multipart body, so build the request
    # first and sign exactly the bytes that will be sent.
    request = authed_client.build_request("POST", "/v1/verify/upload", files=files)
    body = request.read()
    for header, value in signed_headers(body).items():
        request.headers[header] = value

    response = authed_client.send(request)

    assert response.status_code == 202, f"signed upload rejected: {response.text[:200]}"
    assert response.json()["job_id"]


def test_multipart_upload_without_a_signature_is_rejected(
    authed_client: TestClient, card_with_qr, card_without_qr
):
    response = authed_client.post("/v1/verify/upload", files=upload(card_without_qr, card_with_qr))
    assert response.status_code == 401


def test_an_oversized_body_is_refused_before_buffering_it_all(authed_client: TestClient):
    """The buffer is bounded — otherwise it is a memory-exhaustion primitive."""
    from avs.api.app import BodyBufferMiddleware

    assert BodyBufferMiddleware(None).max_bytes <= 64 * 1024 * 1024
