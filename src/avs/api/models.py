"""API request and response models — Step 7. CONTRACTS.md §8."""

from __future__ import annotations

from pydantic import Field, HttpUrl

from avs.contracts import AvsModel, Strictness, VerificationResult

__all__ = ["JobAccepted", "JobStatusResponse", "ReadyResponse", "VerifyUrlRequest"]


class VerifyUrlRequest(AvsModel):
    """Verify from pre-signed URLs.

    ⚠ Both URLs are fetched by the service. See ``avs.storage.fetcher`` — this
      is an SSRF surface and every fetch is checked against the resolved IP.
    """

    front_url: HttpUrl = Field(description="Pre-signed URL for the FRONT of the card")
    back_url: HttpUrl = Field(description="Pre-signed URL for the BACK of the card")
    job_id: str | None = Field(
        default=None,
        description="Caller-supplied id. Submitting the same id twice returns the "
        "existing job rather than verifying again.",
    )
    tenant_id: str | None = None
    employee_id: str | None = None
    callback_url: str | None = None
    strictness: Strictness | None = None


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
