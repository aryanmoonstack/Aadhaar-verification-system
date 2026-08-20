"""API request and response models — Step 7. CONTRACTS.md §8."""

from __future__ import annotations

from pydantic import Field, HttpUrl

from avs.contracts import AvsModel, DecisionStatus, Strictness, VerificationResult

__all__ = [
    "Decision",
    "JobAccepted",
    "JobStatusResponse",
    "ReadyResponse",
    "VerifyUrlRequest",
]


class Decision(AvsModel):
    """The three fields a front end needs, pre-computed. CONTRACTS.md §1.

    ★ WHY THIS EXISTS
      Everything needed to render an upload screen was already in
      ``VerificationResult`` — but only if the client correctly combined
      ``verdict`` with ``proof.valid``, and correctly grouped nine verdicts into
      the two or three cases a screen can show.

      That is real logic, and every client would have to reimplement it: the
      Next.js route, the Spring service, any future mobile app. The rule
      "APPROVED requires a valid signature" is far too important to be
      re-derived correctly three times. It is computed once, here.

    ⛔ ``status`` is NOT a verdict and there is no REJECTED value. See
       ``DecisionStatus``.
    """

    status_code: int = Field(
        description="⛔ Carried in the BODY, not the HTTP status of the request. "
        "Polling a job that failed verification is a SUCCESSFUL poll — HTTP 200 "
        "with a body saying RETRY. 200 approved / 422 retry / 202 review."
    )
    status: DecisionStatus
    message: str = Field(
        description="⛔ Show this verbatim. It is worded so that it never accuses "
        "anyone of forgery — CONTRACTS.md §1 forbids the word 'fake' in "
        "employee-facing text, because a genuine card photographed badly is not one."
    )
    needs_review: bool = Field(
        default=False,
        description="⚠ Independent of `status`. TAMPERED tells the employee to "
        "retry AND alerts a reviewer; one status cannot carry both, so they "
        "travel side by side.",
    )
    verdict: str = Field(
        description="The underlying verdict, unabridged. Anything MAKING a "
        "decision — HR routing, the database constraint, the audit trail — must "
        "read this, never the projected `status`."
    )
    signature_valid: bool = Field(
        default=False,
        description="⛔ APPROVED is only trustworthy alongside this being true. "
        "Both are supplied so a client can assert the pair rather than trust one.",
    )


class VerifyUrlRequest(AvsModel):
    """Verify from pre-signed URLs.

    ⚠ Both URLs are fetched by the service. See ``avs.storage.fetcher`` — this
      is an SSRF surface and every fetch is checked against the resolved IP.
    """

    front_url: HttpUrl = Field(description="Pre-signed URL for the FRONT, or for a whole PDF")
    back_url: HttpUrl | None = Field(
        default=None,
        description="Pre-signed URL for the BACK. Required for images; omit when "
        "front_url points at a PDF, whose pages already carry both faces. "
        "CONTRACTS.md §11.",
    )
    job_id: str | None = Field(
        default=None,
        description="Caller-supplied id. Submitting the same id twice returns the "
        "existing job rather than verifying again.",
    )
    tenant_id: str | None = None
    employee_id: str | None = None
    callback_url: str | None = None
    strictness: Strictness | None = None

    password: str | None = Field(
        default=None,
        description="Password for an encrypted PDF. e-Aadhaar files downloaded "
        "from UIDAI are password-protected, so this is routine. Held in memory "
        "only — never logged, audited or returned.",
    )


class JobAccepted(AvsModel):
    job_id: str
    status: str
    estimated_seconds: int
    already_queued: bool = Field(
        default=False,
        description="True when this job_id was already in flight — the retry was "
        "absorbed rather than duplicating the work.",
    )


class JobStatusResponse(AvsModel):
    job_id: str

    status: str
    """⚠ JOB LIFECYCLE — 'PENDING' or 'DONE'. Not the verification outcome.

    ⛔ Do not confuse with ``decision.status``, which is APPROVED / RETRY /
       REVIEW. This field kept its original meaning deliberately: every existing
       consumer polls on `status == 'DONE'`, and redefining it would have broken
       all of them silently rather than loudly."""

    decision: Decision | None = None
    """The pre-computed answer for a front end. Null until the job settles."""

    result: VerificationResult | None = None
    error: str | None = None
    queued_ms: int = 0
    duration_ms: int | None = None


class ReadyResponse(AvsModel):
    """★ Readiness is about capability, not liveness.

    A service with an empty trust store is running perfectly and cannot approve
    a single genuine document. Only it knows that, so it has to say so.
    """

    ready: bool
    certificates: int
    certificate_status: str
    days_to_certificate_expiry: int | None = None
    decoders: list[str] = Field(default_factory=list)
    queue_depth: int = 0
    reason: str | None = None

    pinning_enabled: bool = False
    """⚠ False means anyone who can write to certs/ can add a certificate and
    mint approvals. Visible here so it shows up in a health dashboard rather
    than only in a startup log nobody reads. Does NOT fail readiness — an
    unpinned service still verifies correctly; it is simply easier to subvert."""

    tenants: int = 0
    auth_required: bool = True
    audit_enabled: bool = False
