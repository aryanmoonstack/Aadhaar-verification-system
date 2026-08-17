"""Frozen domain models — see CONTRACTS.md sections 4, 5, 8.

⛔ FROZEN. Field names here are used in the API, the database, and every module.
   Renaming a field is a breaking change requiring a CONTRACTS.md version bump.

Note on ``AadhaarIdentity``: there is deliberately NO field for the full 12-digit
Aadhaar number. It is not present in the Secure QR — only the last four digits are.
No code path may construct one. See CONTRACTS.md §4.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from avs.contracts.enums import (
    CaptureMethod,
    CardSide,
    CheckName,
    CheckResult,
    DocType,
    ErrorCode,
    Strictness,
    Verdict,
)

__all__ = [
    "AadhaarAddress",
    "AadhaarIdentity",
    "AiTrace",
    "AvsError",
    "AvsModel",
    "CardSideOutcome",
    "CheckOutcome",
    "ClientHints",
    "DecodeResult",
    "DocTypePrediction",
    "ExpectedIdentity",
    "ImageVariant",
    "MatchOutcome",
    "NameSimilarity",
    "QrPayload",
    "QrRegion",
    "QualityScores",
    "SignatureProof",
    "TextSimilarity",
    "ValidatedImage",
    "VerificationResult",
    "VerifyPolicy",
    "VerifyRequest",
]


class AvsModel(BaseModel):
    """Base for all AVS models. Strict by default — unknown fields are an error,
    which prevents a later step silently inventing a field the contract doesn't have.
    """

    model_config = ConfigDict(extra="forbid", frozen=False, str_strip_whitespace=True)


# --------------------------------------------------------------------------- #
# Input pipeline
# --------------------------------------------------------------------------- #


class ValidatedImage(AvsModel):
    """Output of ``ingest/`` (Step 3). An image proven safe to process."""

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    data: bytes = Field(repr=False, description="Normalised image bytes (never logged)")
    mime_type: str
    width: int
    height: int
    size_bytes: int
    sha256: str
    capture_method: CaptureMethod = CaptureMethod.UNKNOWN

    def __repr__(self) -> str:  # never leak bytes into logs or tracebacks
        return (
            f"ValidatedImage(mime={self.mime_type}, {self.width}x{self.height}, "
            f"{self.size_bytes}B, sha256={self.sha256[:12]}…)"
        )


class QualityScores(AvsModel):
    """Output of ``ai/quality/`` (Step 14). Advisory only — never affects the verdict."""

    blur: float = Field(ge=0.0, le=1.0, description="1.0 = perfectly sharp")
    glare: float = Field(ge=0.0, le=1.0, description="1.0 = no glare")
    skew_degrees: float
    resolution_adequate: bool
    crop_complete: bool = Field(description="Is the QR fully inside the frame?")
    shadow: float = Field(ge=0.0, le=1.0)
    decodability: float = Field(
        ge=0.0, le=1.0, description="Predicted probability the QR will decode"
    )
    model_version: str | None = None


class QrRegion(AvsModel):
    """Output of ``ai/localize/`` (Step 15). Bounding box in source-image pixels."""

    x: int
    y: int
    width: int
    height: int
    confidence: float = Field(ge=0.0, le=1.0)
    model_version: str | None = None


class ImageVariant(AvsModel):
    """One preprocessing variant produced by ``imaging/`` (Step 4)."""

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    data: bytes = Field(repr=False)
    strategy: str = Field(description="e.g. 'clahe+otsu+rot90'")
    rotation: int = 0


class DocTypePrediction(AvsModel):
    """Output of ``ai/classify/`` (Step 13)."""

    doc_type: DocType
    confidence: float = Field(ge=0.0, le=1.0)
    model_version: str | None = None


class DecodeResult(AvsModel):
    """Output of ``qr/`` (Step 5)."""

    success: bool
    raw_payload: str | None = Field(
        default=None, repr=False, description="Raw QR string — NEVER logged"
    )
    decoder: str | None = Field(default=None, description="Which cascade stage succeeded")
    strategy: str | None = None
    attempts: int = Field(default=0, description="Variants consumed before stopping")
    restoration_used: bool = False
    foreign_qr_found: bool = Field(
        default=False,
        description="A QR was decoded but it was not an Aadhaar Secure QR — a URL "
        "sticker, an app UI, or the wrong document. Distinguishing this from 'no "
        "QR at all' lets the employee be told something useful.",
    )


# --------------------------------------------------------------------------- #
# Cryptographic core
# --------------------------------------------------------------------------- #


class AadhaarAddress(AvsModel):
    """Address fields from the Secure QR. Canonical names — CONTRACTS.md §4."""

    care_of: str | None = None
    house: str | None = None
    street: str | None = None
    landmark: str | None = None
    location: str | None = None
    vtc: str | None = None
    sub_district: str | None = None
    district: str | None = None
    state: str | None = None
    pincode: str | None = None
    post_office: str | None = None


class AadhaarIdentity(AvsModel):
    """Identity fields from the Secure QR.

    ⛔ There is no field for the full 12-digit Aadhaar number, by design.
       It is not present in the QR. See CONTRACTS.md §4.
    """

    name: str
    dob: str = Field(description="As printed on the card; normalised downstream")
    gender: str
    aadhaar_last4: str = Field(min_length=4, max_length=4)
    reference_id: str = Field(repr=False, description="last4 + timestamp — hashed before storage")

    @field_validator("aadhaar_last4")
    @classmethod
    def _exactly_four_digits(cls, v: str) -> str:
        if not (len(v) == 4 and v.isdigit()):
            raise ValueError("aadhaar_last4 must be exactly 4 digits")
        return v


class QrPayload(AvsModel):
    """Output of ``parser/`` (Step 1). The unpacked, not-yet-verified QR contents.

    ⚠ ``signed_bytes`` and ``signature`` embody the security invariant in
      CONTRACTS.md §5:  signed_bytes = payload[:-256],  signature = payload[-256:]
      Changing how these are derived requires re-running the full corpus.
    """

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    version: str = Field(description="QR format version marker, e.g. 'V2'")
    identity: AadhaarIdentity
    address: AadhaarAddress
    mobile_hash: str | None = Field(default=None, repr=False)
    email_hash: str | None = Field(default=None, repr=False)
    photo: bytes | None = Field(default=None, repr=False, description="JPEG2000 bytes")

    signed_bytes: bytes = Field(repr=False, description="payload[:-256] — the signed region")
    signature: bytes = Field(repr=False, description="payload[-256:] — RSA-2048 signature")

    is_legacy_unsigned: bool = Field(
        default=False, description="Pre-2018 QR — carries data but no signature"
    )


class SignatureProof(AvsModel):
    """Output of ``crypto/`` (Step 1). ★ THE VERDICT-BEARING RESULT ★

    ``valid is True`` is the ONLY condition under which Verdict.VERIFIED may be
    produced. See CONTRACTS.md §1 Rule 1 and §7.
    """

    valid: bool
    certificate_serial: str | None = None
    certificate_subject: str | None = None
    qr_version: str | None = None
    signed_byte_length: int = 0
    algorithm: str = "RSA-2048/SHA-256/PKCS1v15"
    error: ErrorCode | None = None

    certificate_expired: bool = False
    """True when the matching certificate is past its validity window TODAY.

    ⚠ This does NOT make the signature invalid, and must never be allowed to
      influence the verdict. UIDAI rotates its Secure QR signing certificate
      every few years and an e-Aadhaar keeps the signature it was issued with
      forever. Requiring a currently-valid certificate would mean every document
      issued before the last rotation is reported TAMPERED — a false accusation
      of forgery against the majority of real cards.

      It is surfaced for operations (renew the trust store) and for audit
      (which anchor approved this), not for the decision.
    """


# --------------------------------------------------------------------------- #
# Decision layer
# --------------------------------------------------------------------------- #


class CheckOutcome(AvsModel):
    """One entry in ``checks[]``.

    ``rules/`` consumes ONLY these objects. It has no access to raw model
    confidences, which is how the AI boundary (CONTRACTS.md §7) is enforced.
    """

    name: CheckName
    result: CheckResult
    detail: str | None = None
    error: ErrorCode | None = None
    model_version: str | None = Field(default=None, description="Set for AI-produced checks")
    duration_ms: int | None = None


class TextSimilarity(AvsModel):
    """Output of ``ocr/`` (Step 17). Advisory only — routes to review, never rejects."""

    name_similarity: float = Field(ge=0.0, le=1.0)
    dob_match: bool
    last4_match: bool
    overall: float = Field(ge=0.0, le=1.0)
    ocr_engine: str | None = None


class NameSimilarity(AvsModel):
    """Output of ``ai/namematch/`` (Step 18). Advisory only."""

    score: float = Field(ge=0.0, le=1.0)
    phonetic_score: float | None = None
    embedding_score: float | None = None
    literal_score: float | None = None
    explanation: str | None = Field(
        default=None, description="e.g. 'transliteration variant: Dheeraj/Dhiraj'"
    )
    model_version: str | None = None


class MatchOutcome(AvsModel):
    """Output of ``matching/`` (Step 18)."""

    name_matched: bool
    name_similarity: NameSimilarity | None = None
    dob_matched: bool
    is_duplicate: bool
    duplicate_employee_ref: str | None = None


class CardSideOutcome(AvsModel):
    """What happened to one face of the card. See CONTRACTS.md §11.

    Retained per side so a human reviewer can see exactly which image failed and
    why — "the back decoded, the front was too blurry" is actionable; "document
    could not be verified" is not.
    """

    side: CardSide
    ingested: bool = False
    decoded: bool = False
    payload_kind: str | None = Field(
        default=None, description="secure_qr | legacy_xml — never the payload itself"
    )
    decoder: str | None = None
    strategy: str | None = None
    variants_tried: int = 0
    foreign_qr_found: bool = False
    error: ErrorCode | None = None
    processing_ms: int = 0


class AiTrace(AvsModel):
    """Which models ran, for the audit log. Recorded on every verification."""

    models_used: list[str] = Field(default_factory=list)
    restoration_invoked: bool = False
    total_ai_ms: int = 0
    degraded: list[str] = Field(
        default_factory=list, description="Models that failed to load and were skipped"
    )


class VerificationResult(AvsModel):
    """Final output of ``rules/`` (Step 6), after ``privacy/`` filtering."""

    job_id: str
    verdict: Verdict
    method: str = "SECURE_QR_RSA2048"
    proof: SignatureProof | None = None
    identity: AadhaarIdentity | None = None
    address: AadhaarAddress | None = None
    reference_hash: str | None = Field(
        default=None, description="Salted HMAC of reference_id — safe to store"
    )
    checks: list[CheckOutcome] = Field(default_factory=list)
    sides: list[CardSideOutcome] = Field(
        default_factory=list,
        description="Per-side outcomes. CONTRACTS.md §11 — the verdict is per "
        "DOCUMENT, but reviewers need to see which face failed.",
    )
    ai_trace: AiTrace = Field(default_factory=AiTrace)
    user_message: str = ""
    user_message_localised: dict[str, str] = Field(default_factory=dict)
    error: ErrorCode | None = None
    processing_ms: int = 0
    verified_at: datetime | None = None
    purge_after: datetime | None = None

    @property
    def is_auto_approve(self) -> bool:
        """Belt and braces: VERIFIED alone is not enough — the proof must be valid.

        This double-check exists so that even a bug in ``rules/`` cannot produce an
        approval without a cryptographic signature behind it.
        """
        return self.verdict.is_auto_approve and self.proof is not None and self.proof.valid is True


class AvsError(AvsModel):
    """Structured error — CONTRACTS.md §3."""

    code: ErrorCode
    message: str
    retryable: bool = False
    request_id: str | None = None
    detail: dict[str, Any] | None = None


# --------------------------------------------------------------------------- #
# API request models — CONTRACTS.md §8
# --------------------------------------------------------------------------- #


class ExpectedIdentity(AvsModel):
    """Profile values to match against, supplied by the HRM."""

    name: str | None = None
    dob: date | None = None


class VerifyPolicy(AvsModel):
    strictness: Strictness = Strictness.STANDARD
    name_match_threshold: float = Field(default=0.85, ge=0.0, le=1.0)
    enable_restoration: bool = True
    enable_ocr_cross_check: bool = True


class ClientHints(AvsModel):
    """Signals from the browser-side AI (Step 16). Advisory only."""

    capture_method: CaptureMethod = CaptureMethod.UNKNOWN
    client_quality_score: float | None = Field(default=None, ge=0.0, le=1.0)
    client_qr_precheck: CheckResult | None = None


class VerifyRequest(AvsModel):
    job_id: str
    tenant_id: str
    employee_id: str
    document_id: str
    source_url: str
    expected: ExpectedIdentity = Field(default_factory=ExpectedIdentity)
    policy: VerifyPolicy = Field(default_factory=VerifyPolicy)
    client_hints: ClientHints = Field(default_factory=ClientHints)
    callback_url: str | None = None
