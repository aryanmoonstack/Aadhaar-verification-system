"""FastAPI application — Step 7.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 7
Provides : create_app(), the /v1 routes, health probes
Consumes : avs.pipeline, avs.worker, avs.storage, avs.truststore, avs.contracts
Used by  : Spring AvsClient (Step 10)
Status   : COMPLETE

ROUTES
    POST /v1/verify          JSON, pre-signed URLs      -> 202
    POST /v1/verify/upload   multipart, raw bytes       -> 202
    POST /v1/verify/sync     multipart, blocking        -> 200   (admin/debug)
    GET  /v1/verify/{job_id} poll                       -> 200
    GET  /health             liveness
    GET  /ready              readiness — fails on an empty trust store
    GET  /metrics            Prometheus

TWO UPLOAD PATHS, DELIBERATELY
------------------------------
Multipart makes local testing and early Spring integration trivial — no object
storage needed to try anything. Pre-signed URLs stop Spring holding two images in
memory and forwarding them once S3/MinIO exists. Supporting both lets the
integration start simple and migrate without an API change.

⚠ The URL path is an SSRF surface. Every fetch goes through
  ``SafeUrlFetcher``, which resolves the host and refuses loopback, private,
  link-local and reserved addresses — see ``avs.storage.fetcher``.

READINESS IS NOT LIVENESS
-------------------------
``/health`` says the process is alive. ``/ready`` says it can do its job, which
here means **the trust store has a usable certificate**. A service with an empty
trust store answers every request with ``ERROR``; it must not receive traffic,
and a load balancer can only know that if we tell it.
"""

from __future__ import annotations

import threading
import time
import uuid
from contextlib import asynccontextmanager
from typing import Annotated, Any

import structlog
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse

from avs import __version__
from avs.api.callbacks import CallbackDispatcher
from avs.api.models import (
    Decision,
    JobAccepted,
    JobStatusResponse,
    ReadyResponse,
    VerifyUrlRequest,
)
from avs.audit import AuditEntry, AuditSink, FileAuditTrail, NullAuditSink, utc_now
from avs.contracts import CardSide, DecisionStatus, ErrorCode, Strictness
from avs.crypto import SecureQrVerifier
from avs.ingest import FileKind, detect
from avs.logging import configure_logging, get_logger
from avs.pipeline import DocumentVerifier, SideInput
from avs.privacy import DataMinimisingFilter
from avs.qr import decoder_availability
from avs.security import (
    HEADER_NONCE,
    HEADER_SIGNATURE,
    HEADER_TENANT,
    HEADER_TIMESTAMP,
    InMemoryTenantRegistry,
    NonceCache,
    TenantRegistry,
    verify_request_signature,
)
from avs.storage import FetchError, SafeUrlFetcher, is_safe_url
from avs.truststore import FileCertificateStore, TrustStoreError
from avs.worker import InProcessJobQueue, QueueFull

__all__ = ["AppState", "create_app"]

log = get_logger(__name__)


class AppState:
    """Everything built once at startup and shared across requests."""

    def __init__(
        self,
        *,
        verifier: DocumentVerifier,
        queue: InProcessJobQueue,
        fetcher: SafeUrlFetcher,
        dispatcher: CallbackDispatcher,
        trust_store: FileCertificateStore | None,
        audit: AuditSink | None = None,
        tenants: TenantRegistry | None = None,
        require_auth: bool = True,
    ) -> None:
        self.verifier = verifier
        self.queue = queue
        self.fetcher = fetcher
        self.dispatcher = dispatcher
        self.trust_store = trust_store
        self.audit = audit or NullAuditSink()
        self.tenants = tenants or InMemoryTenantRegistry()
        self.require_auth = require_auth
        self.nonces = NonceCache()
        self.started_at = time.time()
        self.counters: dict[str, int] = {}
        # Counters are written from worker threads and read by /metrics on the
        # event loop. `d[k] = d.get(k, 0) + 1` is a read-modify-write, so two
        # workers finishing together can lose a count. Cheap to guard, and a
        # metric that silently undercounts is worse than no metric.
        self._counter_lock = threading.Lock()

    def count_value(self, name: str, amount: int) -> None:
        """Accumulate a measured quantity rather than an occurrence."""
        with self._counter_lock:
            self.counters[name] = self.counters.get(name, 0) + amount

    def count(self, name: str, amount: int = 1) -> None:
        with self._counter_lock:
            self.counters[name] = self.counters.get(name, 0) + amount

    def counter_snapshot(self) -> dict[str, int]:
        with self._counter_lock:
            return dict(self.counters)


def get_state(request: Request) -> AppState:
    return request.app.state.avs  # type: ignore[no-any-return]


State = Annotated[AppState, Depends(get_state)]


class RequestContextMiddleware:
    """One id per request, bound into every log line it produces — Step 9.

    ⛔ WITHOUT THIS, DEBUGGING A REAL COMPLAINT IS GUESSWORK.

       An employee says "my Aadhaar was rejected on Tuesday afternoon". The
       verification touched ingest, imaging, the decoder cascade, the parser,
       crypto and the rules engine, each logging independently, interleaved with
       every other document being processed concurrently. Without a shared id
       there is no way to pull out the lines belonging to THAT document.

    The id is taken from the caller's ``X-Request-ID`` when supplied — so a
    trace begun in the HRM continues here rather than restarting — and echoed
    back so the caller can quote it in a support ticket.
    """

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        request_id = headers.get("x-request-id") or uuid.uuid4().hex[:16]
        scope["avs_request_id"] = request_id

        structlog.contextvars.bind_contextvars(request_id=request_id)

        async def send_with_id(message):
            if message["type"] == "http.response.start":
                message.setdefault("headers", [])
                message["headers"].append((b"x-request-id", request_id.encode("latin-1")))
            await send(message)

        try:
            await self.app(scope, receive, send_with_id)
        finally:
            # ⚠ Must be cleared. Context variables outlive the request in a
            #   worker thread pool, so leaving it bound leaks one request's id
            #   into the next request's logs — worse than having no id at all,
            #   because it is confidently wrong.
            structlog.contextvars.unbind_contextvars("request_id")


class BodyBufferMiddleware:
    """Buffer the request body so BOTH the signature check and the route can read it.

    ⛔ THE BUG THIS FIXES WOULD HAVE BROKEN EVERY FILE UPLOAD.

       An ASGI request body is a one-shot stream. FastAPI reads the multipart
       form BEFORE it solves dependencies, so by the time the authentication
       dependency asked for `request.body()` the stream was gone and Starlette
       raised "Stream consumed". Auth worked on JSON routes and broke every
       multipart upload — the route the HRM actually uses.

       Caching on the Request object is not enough either: the route handler
       builds its own Request from the same scope, so a cached attribute does
       not carry across.

       So the body is read here, once, before routing, and `receive` is replaced
       with one that replays it. Everything downstream sees a normal stream.

    The buffer is bounded. Without a cap this would read an unbounded upload
    fully into memory before any size check could run — a trivial denial of
    service.
    """

    def __init__(self, app, *, max_bytes: int = 32 * 1024 * 1024) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        chunks: list[bytes] = []
        total = 0
        more = True
        while more:
            message = await receive()
            if message["type"] != "http.request":
                break
            chunk = message.get("body", b"")
            total += len(chunk)
            if total > self.max_bytes:
                response = JSONResponse(
                    status_code=413,
                    content={
                        "code": ErrorCode.FILE_TOO_LARGE.value,
                        "message": f"request body exceeds {self.max_bytes} bytes",
                        "retryable": False,
                    },
                )
                await response(scope, receive, send)
                return
            chunks.append(chunk)
            more = message.get("more_body", False)

        body = b"".join(chunks)
        scope["avs_body"] = body

        sent = False

        async def replay():
            nonlocal sent
            if sent:
                return {"type": "http.disconnect"}
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}

        await self.app(scope, replay, send)


async def authenticate(request: Request) -> str:
    """⛔ Every /v1 route goes through here. Step 7 had NO authentication.

    Returns the authenticated tenant id.

    The 401 body is deliberately opaque. Distinguishing "unknown tenant" from
    "bad signature" from "replayed nonce" hands an attacker a working oracle for
    enumerating tenants and probing the scheme. Our logs carry the real reason;
    the caller gets one word.
    """
    state: AppState = request.app.state.avs

    if not state.require_auth:
        # Development only. `avs serve --no-auth` prints a loud warning.
        return "anonymous"

    # Buffered by BodyBufferMiddleware before routing — see the note there.
    # Reading it here directly would raise "Stream consumed" on every multipart
    # upload, because FastAPI parses the form before solving dependencies.
    body = request.scope.get("avs_body", b"")
    check = verify_request_signature(
        tenant_id=request.headers.get(HEADER_TENANT),
        signature=request.headers.get(HEADER_SIGNATURE),
        timestamp=request.headers.get(HEADER_TIMESTAMP),
        nonce=request.headers.get(HEADER_NONCE),
        body=body,
        secret_for=state.tenants.secret_for,
        nonce_cache=state.nonces,
    )

    if not check.ok:
        log.warning(
            "request_rejected",
            tenant=check.tenant_id,
            reason=check.reason,
            path=request.url.path,
        )
        state.count("auth_rejected")
        raise HTTPException(
            status_code=401,
            detail={
                "code": ErrorCode.INVALID_REQUEST.value,
                "message": "authentication failed",
                "retryable": False,
            },
        )

    return check.tenant_id or "unknown"


Tenant = Annotated[str, Depends(authenticate)]


# --------------------------------------------------------------------------- #


def create_app(
    *,
    cert_dir: str = "certs",
    hash_secret: str = "",
    strictness: Strictness = Strictness.STANDARD,
    workers: int = 2,
    max_queued: int = 32,
    time_budget_seconds: float = 12.0,
    allow_private_urls: bool = False,
    callback_secret: str = "",
    audit_path: str | None = None,
    tenants: TenantRegistry | None = None,
    require_auth: bool = True,
) -> FastAPI:
    """Build the application. All wiring happens here, once."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        configure_logging()

        store: FileCertificateStore | None = FileCertificateStore(cert_dir)
        certificates = []
        try:
            store.load()  # type: ignore[union-attr]
            certificates = store.certificates()  # type: ignore[union-attr]
        except TrustStoreError as exc:
            # Start anyway, but /ready will fail. Refusing to boot would mean a
            # rollout stalls with no way to see why; an unready pod is
            # diagnosable from outside.
            log.error("trust_store_unavailable", reason=exc.message)
            store = None

        app.state.avs = AppState(
            verifier=DocumentVerifier(
                SecureQrVerifier(certificates),
                DataMinimisingFilter(hash_secret=hash_secret or "local-development-key"),
                strictness=strictness,
                time_budget_seconds=time_budget_seconds,
            ),
            queue=InProcessJobQueue(workers=workers, max_queued=max_queued),
            fetcher=SafeUrlFetcher(allow_private=allow_private_urls),
            dispatcher=CallbackDispatcher(secret=callback_secret),
            trust_store=store,
            audit=FileAuditTrail(audit_path) if audit_path else NullAuditSink(),
            tenants=tenants,
            require_auth=require_auth,
        )
        if not require_auth:
            log.warning(
                "authentication_disabled",
                detail="every caller is accepted as 'anonymous' — development only",
            )
        log.info(
            "avs_started",
            certificates=len(certificates),
            workers=workers,
            decoders=[n for n, ok in decoder_availability().items() if ok],
            tenants=len(tenants.tenant_ids) if tenants else 0,
            auth="required" if require_auth else "DISABLED",
        )
        yield
        app.state.avs.queue.shutdown(wait=False)

    app = FastAPI(
        title="Aadhaar Verification Service",
        version=__version__,
        description=(
            "Verifies an Aadhaar document by checking the UIDAI RSA-2048 signature "
            "in its Secure QR code. Both card faces are required — the signature "
            "covers the QR payload only, never the printed card."
        ),
        lifespan=lifespan,
    )

    _register_routes(app)
    # Order matters: the outermost middleware runs first, so the request id is
    # bound before anything else can log.
    app.add_middleware(BodyBufferMiddleware)
    app.add_middleware(RequestContextMiddleware)
    return app


# --------------------------------------------------------------------------- #


def _register_routes(app: FastAPI) -> None:
    @app.post("/v1/verify", status_code=202, response_model=JobAccepted, tags=["verify"])
    async def verify_from_urls(
        request: VerifyUrlRequest, state: State, tenant: Tenant
    ) -> JobAccepted:
        """Queue a verification, fetching both images from pre-signed URLs.

        Fetches happen on the worker, not in this handler, so a slow or hanging
        source cannot occupy a request slot.
        """
        job_id = request.job_id or str(uuid.uuid4())

        # ★ Validate BEFORE queuing. The check is a DNS lookup — cheap — and a
        #   400 telling the caller "that URL is not allowed" is far better than a
        #   202 followed by a job that fails a second later for reasons they
        #   cannot see. Refusing early also means a probing attacker gets no
        #   queue slot at all.
        candidates = [("front_url", request.front_url)]
        if request.back_url is not None:
            candidates.append(("back_url", request.back_url))

        for label, url in candidates:
            check = is_safe_url(str(url), allow_private=state.fetcher.allow_private)
            if not check.ok:
                log.warning(
                    "source_url_refused",
                    job_id=job_id,
                    field=label,
                    reason=check.reason,
                    blocked=check.blocked,
                )
                # 400 for a forbidden URL — permanent, no point retrying.
                # 503 for a resolver failure — transient, please do retry.
                raise HTTPException(
                    status_code=400 if check.blocked else 503,
                    detail={
                        "code": (
                            ErrorCode.INVALID_REQUEST.value
                            if check.blocked
                            else ErrorCode.STORAGE_FETCH_FAILED.value
                        ),
                        "message": f"{label} was refused: {check.reason}",
                        "retryable": not check.blocked,
                    },
                )

        async def work() -> Any:
            front = await state.fetcher.fetch(str(request.front_url))
            back = (
                await state.fetcher.fetch(str(request.back_url))
                if request.back_url is not None
                else None
            )
            # ⚠ Checked on the worker, not in the handler. Unlike an upload,
            #   the bytes do not exist until they are fetched — so the "one PDF
            #   is enough, one image is not" rule cannot be applied any earlier.
            _require_two_faces(front, back)
            return _run_pipeline(
                state, job_id, front, back, request.strictness, tenant, request.password
            )

        return await _submit_async(state, job_id, work, request.callback_url)

    @app.post("/v1/verify/upload", status_code=202, response_model=JobAccepted, tags=["verify"])
    async def verify_from_upload(
        state: State,
        tenant: Tenant,
        front: Annotated[UploadFile, File(description="FRONT of the card, or a whole PDF")],
        back: Annotated[UploadFile | None, File(description="BACK of the card")] = None,
        job_id: Annotated[str | None, Form()] = None,
        callback_url: Annotated[str | None, Form()] = None,
        strictness: Annotated[str | None, Form()] = None,
        password: Annotated[str | None, Form()] = None,
    ) -> JobAccepted:
        """Queue a verification from uploaded images or a PDF.

        Two shapes are accepted:

        * **Two images** — ``front`` and ``back``. Both required. CONTRACTS.md §11.
        * **One PDF** — ``front`` alone. Its pages already hold both faces.

        ⚠ ``password`` is for an encrypted PDF. e-Aadhaar files downloaded from
          UIDAI are password-protected, so this is a routine field rather than
          an unusual one.

        ⛔ It is held in memory for the life of the job and never logged,
           audited or returned. ``tests/unit/test_pdf_pipeline.py`` asserts it
           cannot reach the result.
        """
        identifier = job_id or str(uuid.uuid4())
        front_bytes = await front.read()
        back_bytes = await back.read() if back is not None else None
        _require_two_faces(front_bytes, back_bytes)
        level = Strictness(strictness.upper()) if strictness else None

        def work() -> Any:
            return _run_pipeline(
                state, identifier, front_bytes, back_bytes, level, tenant, password
            )

        return _submit(state, identifier, work, callback_url)

    @app.post("/v1/verify/sync", tags=["verify"])
    async def verify_sync(
        state: State,
        tenant: Tenant,
        front: Annotated[UploadFile, File()],
        back: Annotated[UploadFile | None, File()] = None,
        strictness: Annotated[str | None, Form()] = None,
        password: Annotated[str | None, Form()] = None,
    ) -> dict[str, Any]:
        """Blocking verification. Admin and debugging only.

        Holds the connection for the full 7-12 seconds. Present because it makes
        the service trivially testable with curl; not intended for the HRM.
        """
        level = Strictness(strictness.upper()) if strictness else None
        front_bytes = await front.read()
        back_bytes = await back.read() if back is not None else None
        _require_two_faces(front_bytes, back_bytes)

        result = _run_pipeline(
            state,
            str(uuid.uuid4()),
            front_bytes,
            back_bytes,
            level,
            tenant,
            password,
        )
        body = result.model_dump(mode="json")
        # Same projection the polling endpoint returns, so a client written
        # against one shape works against the other.
        decision = _decision_for(result)
        body["decision"] = decision.model_dump(mode="json") if decision else None
        return body

    @app.get("/v1/verify/{job_id}", response_model=JobStatusResponse, tags=["verify"])
    async def get_job(job_id: str, state: State, tenant: Tenant) -> JobStatusResponse:
        job = state.queue.get(job_id)
        if job is None:
            raise HTTPException(
                status_code=404,
                detail={
                    "code": ErrorCode.INVALID_REQUEST.value,
                    "message": "unknown or expired job",
                    "retryable": False,
                },
            )
        return JobStatusResponse(
            job_id=job.job_id,
            status=job.status.value,
            decision=_decision_for(job.result),
            result=job.result,
            error=job.error,
            queued_ms=job.queued_ms,
            duration_ms=job.duration_ms,
        )

    # ── Probes ───────────────────────────────────────────────────────────

    @app.get("/health", tags=["ops"])
    async def health() -> dict[str, str]:
        """Liveness. Says nothing about whether the service can verify."""
        return {"status": "alive", "version": __version__}

    @app.get("/ready", response_model=ReadyResponse, tags=["ops"])
    async def ready(state: State) -> JSONResponse:
        """Readiness. ★ Fails when the trust store cannot approve anything.

        Without a usable certificate every genuine document comes back ERROR.
        The service is running but useless, and only it knows that — so it has to
        say so, or a load balancer will keep sending it work.
        """
        health_report = state.trust_store.health() if state.trust_store else None
        certificates_ok = state.verifier.is_ready
        decoders_ok = any(decoder_availability().values())
        is_ready = certificates_ok and decoders_ok

        body = ReadyResponse(
            ready=is_ready,
            certificates=len(state.verifier.verifier.certificates_loaded),
            certificate_status=health_report.status.value if health_report else "UNAVAILABLE",
            days_to_certificate_expiry=(
                health_report.days_to_earliest_expiry if health_report else None
            ),
            decoders=[name for name, ok in decoder_availability().items() if ok],
            queue_depth=state.queue.depth,
            pinning_enabled=bool(health_report and health_report.pinning_enabled),
            tenants=len(state.tenants.tenant_ids),
            auth_required=state.require_auth,
            audit_enabled=not isinstance(state.audit, NullAuditSink),
            reason=(
                None
                if is_ready
                else (
                    "no usable UIDAI certificate — nothing can be verified"
                    if not certificates_ok
                    else "no QR decoder backend available"
                )
            ),
        )
        return JSONResponse(status_code=200 if is_ready else 503, content=body.model_dump())

    @app.get("/metrics", response_class=PlainTextResponse, tags=["ops"])
    async def metrics(state: State) -> str:
        """Prometheus exposition. Hand-rolled to keep the base install small."""
        lines = [
            "# HELP avs_up Service is running.",
            "# TYPE avs_up gauge",
            "avs_up 1",
            "# HELP avs_ready Service can verify documents.",
            "# TYPE avs_ready gauge",
            f"avs_ready {1 if state.verifier.is_ready else 0}",
            "# HELP avs_queue_depth Jobs queued or running.",
            "# TYPE avs_queue_depth gauge",
            f"avs_queue_depth {state.queue.depth}",
            "# HELP avs_uptime_seconds Seconds since start.",
            "# TYPE avs_uptime_seconds counter",
            f"avs_uptime_seconds {time.time() - state.started_at:.0f}",
        ]

        if state.trust_store is not None:
            report = state.trust_store.health()
            lines += [
                "# HELP avs_certificate_pinning Whether FINGERPRINTS.txt is enforcing "
                "which certificates may be loaded. 0 means anyone who can write to "
                "certs/ can mint approvals.",
                "# TYPE avs_certificate_pinning gauge",
                f"avs_certificate_pinning {1 if report.pinning_enabled else 0}",
            ]
            days = report.days_to_earliest_expiry
            if days is not None:
                lines += [
                    "# HELP avs_certificate_days_to_expiry Days until the earliest "
                    "usable certificate expires. ALERT AT 90.",
                    "# TYPE avs_certificate_days_to_expiry gauge",
                    f"avs_certificate_days_to_expiry {days}",
                ]

        counters = state.counter_snapshot()

        # ★ THE DECODE RATE. The project's primary metric, and until Step 9 it
        #   existed only in an offline script. That is how a real-world rate of
        #   22.7% went unnoticed while 540 tests passed.
        documents = counters.get("documents_total", 0)
        decoded = counters.get("documents_decoded", 0)
        lines += [
            "# HELP avs_documents_total Documents processed.",
            "# TYPE avs_documents_total counter",
            f"avs_documents_total {documents}",
            "# HELP avs_documents_decoded_total Documents where a Secure QR was read.",
            "# TYPE avs_documents_decoded_total counter",
            f"avs_documents_decoded_total {decoded}",
            "# HELP avs_decode_rate Fraction of documents yielding a Secure QR. "
            "ALERT BELOW 0.85 — below that, employees are being asked to re-upload.",
            "# TYPE avs_decode_rate gauge",
            f"avs_decode_rate {decoded / documents if documents else 0:.4f}",
        ]

        if documents:
            mean_ms = counters.get("processing_ms_total", 0) / documents
            lines += [
                "# HELP avs_processing_ms_mean Mean end-to-end processing time.",
                "# TYPE avs_processing_ms_mean gauge",
                f"avs_processing_ms_mean {mean_ms:.0f}",
            ]

        lines += [
            "# HELP avs_verdict_total Verifications by verdict.",
            "# TYPE avs_verdict_total counter",
        ]
        verdicts = {
            "VERIFIED", "TAMPERED", "UNREADABLE", "LEGACY_FORMAT", "WRONG_DOCUMENT",
            "PROFILE_MISMATCH", "TEXT_MISMATCH", "DUPLICATE", "ERROR",
        }  # fmt: skip
        for name, value in sorted(counters.items()):
            if name in verdicts:
                lines.append(f'avs_verdict_total{{verdict="{name}"}} {value}')

        # Which decoder and which preprocessing strategy actually rescued the
        # document. On the real corpus every success came from `original` until
        # Step 7.5 — a regression there would otherwise be silent.
        for prefix, metric, label in (
            ("decoder:", "avs_decoder_success_total", "decoder"),
            ("strategy:", "avs_strategy_success_total", "strategy"),
        ):
            hits = {k[len(prefix) :]: v for k, v in counters.items() if k.startswith(prefix)}
            if hits:
                lines.append(f"# TYPE {metric} counter")
                for name, value in sorted(hits.items()):
                    lines.append(f'{metric}{{{label}="{name}"}} {value}')

        rejected = counters.get("auth_rejected", 0)
        lines += [
            "# HELP avs_auth_rejected_total Requests that failed authentication. "
            "A sustained rise means a misconfigured client or someone probing.",
            "# TYPE avs_auth_rejected_total counter",
            f"avs_auth_rejected_total {rejected}",
        ]

        return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #


def _decision_for(result: Any) -> Decision | None:
    """Project a settled result into the three fields a front end needs.

    ⛔ THE DOWNGRADE ON THE LAST LINE IS THE POINT OF THIS FUNCTION.

       ``Verdict.VERIFIED`` alone does not produce APPROVED here. The proof must
       also be valid. That is CONTRACTS.md §1 Rule 1 restated at the boundary,
       and it means a bug anywhere upstream — the rules engine, the pipeline, a
       future refactor — cannot hand a client an approval with no signature
       behind it. It would arrive as REVIEW instead: visibly wrong, seen by a
       human, rather than quietly approved.

       ``VerificationResult.is_auto_approve`` already applies the same pairing.
       Repeating it is not redundancy for its own sake; this is the last place
       the two facts are together before they leave the service.
    """
    if result is None:
        return None

    verdict = result.verdict
    signature_valid = result.proof is not None and result.proof.valid is True
    status = verdict.decision_status

    if status is DecisionStatus.APPROVED and not signature_valid:
        log.error(
            "approval_without_signature_downgraded",
            job_id=result.job_id,
            verdict=verdict.value,
            detail="VERIFIED arrived with no valid proof — routed to human review",
        )
        status = DecisionStatus.REVIEW

    return Decision(
        status_code=status.http_status,
        status=status,
        message=result.user_message,
        needs_review=verdict.requires_human_review or status is DecisionStatus.REVIEW,
        verdict=verdict.value,
        signature_valid=signature_valid,
    )


def _require_two_faces(front: bytes, back: bytes | None) -> None:
    """Refuse a lone IMAGE. Allow a lone PDF.

    ⛔ WHY THE EXCEPTION IS NOT A WEAKENING — CONTRACTS.md §11

       §11 requires both faces because of one specific attack: take a genuine
       Aadhaar back with a valid Secure QR, pair it with a **forged front**. The
       signature verifies perfectly, because the QR really is genuine; only the
       printed face is fake. Collecting both faces and diffing the printed text
       against the signed QR fields is what closes it.

       That attack needs the two faces to come from **different sources**. Two
       separate photographs can. The pages of one PDF cannot — they arrived as
       one file.

       And note what the old behaviour actually did: an employee holding a
       single PDF had to submit the *same bytes* twice, once per slot. That
       added no evidence whatsoever. It also produced a misleading
       `SIDE_AGREEMENT = PASS, "both sides carry the same payload"` — a
       tautology reading as corroboration. One upload reports `SKIP`, which is
       the truth.

    ⚠ What this does NOT fix: a PDF containing only a QR page and no printed
      face leaves the Step 17 cross-check nothing to compare. That was equally
      true when the same file was uploaded twice, so nothing regressed — but it
      is a real limit, not a solved problem.
    """
    if back is not None:
        return

    if detect(front).kind is FileKind.PDF:
        return

    raise HTTPException(
        status_code=400,
        detail={
            "code": ErrorCode.INVALID_REQUEST.value,
            "message": "a single image is not enough; upload both faces, or one PDF",
            "user_message": (
                "Please upload both the front and the back of your Aadhaar card. "
                "If you have the Aadhaar PDF, you can upload that on its own instead."
            ),
            "retryable": True,
        },
    )


def _run_pipeline(
    state: AppState,
    job_id: str,
    front: bytes,
    back: bytes | None,
    strictness: Strictness | None,
    tenant_id: str = "unknown",
    password: str | None = None,
) -> Any:
    verifier = state.verifier
    if strictness is not None and strictness is not verifier.strictness:
        # Per-request override. Cheap to build — the heavy components (trust
        # store, decoders) are shared by reference.
        verifier = DocumentVerifier(
            verifier.verifier,
            verifier.privacy,
            ingestor=verifier.ingestor,
            generator=verifier.generator,
            cascade=verifier.cascade,
            parser=verifier.parser,
            strictness=strictness,
            time_budget_seconds=verifier.time_budget_seconds,
        )

    # ⚠ One SideInput when a PDF was submitted alone. The pipeline is already
    #   agnostic about how many it receives — `_side_agreement` compares a SET
    #   of payloads, so one entry simply has nothing to compare and reports
    #   SKIP. Nothing here needed a special case; the guard above is what
    #   decides whether a single upload was legitimate in the first place.
    inputs = [SideInput(CardSide.FRONT, front, password=password)]
    if back is not None:
        inputs.append(SideInput(CardSide.BACK, back, password=password))

    result = verifier.verify(inputs, job_id=job_id)
    state.count(result.verdict.value)

    # ★ THE DECODE RATE — the project's primary metric, never instrumented
    #   until now. It is the number that revealed 22.7% on real photos, and it
    #   was only visible because a script measured it offline. Production must
    #   report it continuously or the next regression is invisible.
    state.count("documents_total")
    decoded_sides = [s for s in result.sides if s.decoded]
    if decoded_sides:
        state.count("documents_decoded")
        winner = decoded_sides[0]
        if winner.decoder:
            state.count(f"decoder:{winner.decoder}")
        if winner.strategy:
            # Which preprocessing rescued it. On the real corpus this was
            # `original` every time until the Step 7.5 fix — a fact worth
            # watching for, not rediscovering.
            state.count(f"strategy:{winner.strategy}")
    state.count_value("processing_ms_total", result.processing_ms)

    proof = result.proof
    state.audit.record(
        AuditEntry(
            job_id=job_id,
            tenant_id=tenant_id,
            verdict=result.verdict.value,
            at=utc_now(),
            signature_valid=bool(proof and proof.valid),
            certificate_serial=proof.certificate_serial if proof else None,
            certificate_expired=bool(proof and proof.certificate_expired),
            qr_version=proof.qr_version if proof else None,
            reference_hash=result.reference_hash,
            decoded=bool(decoded_sides),
            decoder=decoded_sides[0].decoder if decoded_sides else None,
            strategy=decoded_sides[0].strategy if decoded_sides else None,
            variants_tried=sum(s.variants_tried for s in result.sides),
            processing_ms=result.processing_ms,
            error_code=result.error.value if result.error else None,
        )
    )
    log.info(
        "verification_complete",
        job_id=job_id,
        verdict=result.verdict.value,
        processing_ms=result.processing_ms,
    )
    return result


def _submit(state: AppState, job_id: str, work: Any, callback_url: str | None) -> JobAccepted:
    def wrapped() -> Any:
        result = work()
        if callback_url:
            state.dispatcher.send(callback_url, result)
        return result

    try:
        job, created = state.queue.submit(job_id, wrapped)
    except QueueFull as exc:
        raise HTTPException(
            status_code=503,
            detail={
                "code": ErrorCode.RATE_LIMITED.value,
                "message": str(exc),
                "retryable": True,
            },
            headers={"Retry-After": "10"},
        ) from exc

    return JobAccepted(
        job_id=job.job_id,
        status=job.status.value,
        estimated_seconds=12,
        already_queued=not created,
    )


async def _submit_async(
    state: AppState, job_id: str, coroutine_factory: Any, callback_url: str | None
) -> JobAccepted:
    """Submit work that needs an event loop (URL fetching) to the thread pool."""
    import asyncio

    def runner() -> Any:
        try:
            return asyncio.run(coroutine_factory())
        except FetchError as exc:
            log.warning("source_fetch_failed", job_id=job_id, blocked=exc.blocked)
            raise

    return _submit(state, job_id, runner, callback_url)
