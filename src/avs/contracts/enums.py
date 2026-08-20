"""Frozen enumerations — see CONTRACTS.md sections 1, 2, 3, 9.

⛔ These values are FROZEN. Steps 1-25 are built against them.
   Adding a member is a breaking change requiring a CONTRACTS.md version bump
   and a review of every consumer listed in PROJECT_STATE.md.
"""

from __future__ import annotations

from enum import Enum

__all__ = [
    "CaptureMethod",
    "CardSide",
    "CheckName",
    "CheckResult",
    "DecisionStatus",
    "DocType",
    "ErrorCode",
    "Strictness",
    "Verdict",
]


class DecisionStatus(str, Enum):
    """What the EMPLOYEE should do next. A projection of ``Verdict``, not a verdict.

    ⛔ This is not a tenth verdict and must never be treated as one. CONTRACTS.md
       §1 fixes the verdict set at nine; this enum is a lossy view of them built
       for one audience — the person staring at an upload screen, who cannot act
       on the difference between LEGACY_FORMAT and WRONG_DOCUMENT. Both mean
       "send us something else".

       The verdict remains in the response. Anything making a decision — HR
       routing, the database CHECK constraint, the audit trail — reads the
       verdict, never this.

    ⛔ THERE IS NO ``REJECTED`` MEMBER, DELIBERATELY.

       CONTRACTS.md §1 Rule 2 is absolute: nothing is ever auto-rejected. A
       genuine card photographed badly is indistinguishable from a forgery to
       any automated check, which is exactly why no automated check may call it
       one. On the measured corpus roughly 70% of unguided photographs failed to
       decode — a REJECTED status would have accused most of those employees of
       fraud.

    ⚠ RETRY and REVIEW are about the EMPLOYEE's next action, and are separate
      from whether HR is alerted. See ``requires_human_review`` — TAMPERED is
      both: the employee should re-upload, *and* a reviewer should look. One
      status cannot carry both, so the two travel side by side.
    """

    APPROVED = "APPROVED"
    """Verified against a UIDAI certificate. The only auto-approval."""

    RETRY = "RETRY"
    """The employee can fix this by uploading again — a clearer photo, the other
    document, the password. Never an accusation."""

    REVIEW = "REVIEW"
    """A human decides. Re-uploading cannot change the outcome, so asking the
    employee to try again would waste their time and mislead them."""

    @property
    def http_status(self) -> int:
        """The code carried in the response BODY as ``status_code``.

        ⛔ Not the HTTP status of the poll itself. Fetching a job that failed
           verification is a *successful* fetch — it returns 200 with a body
           saying RETRY. Conflating the two would mean a client's error handling
           fired on a perfectly good response.
        """
        return {
            DecisionStatus.APPROVED: 200,
            DecisionStatus.RETRY: 422,
            DecisionStatus.REVIEW: 202,
        }[self]


class Verdict(str, Enum):
    """The complete set of verification outcomes. Exactly nine. See CONTRACTS.md §1."""

    VERIFIED = "VERIFIED"
    TAMPERED = "TAMPERED"
    UNREADABLE = "UNREADABLE"
    LEGACY_FORMAT = "LEGACY_FORMAT"
    WRONG_DOCUMENT = "WRONG_DOCUMENT"
    PROFILE_MISMATCH = "PROFILE_MISMATCH"
    TEXT_MISMATCH = "TEXT_MISMATCH"
    DUPLICATE = "DUPLICATE"
    ERROR = "ERROR"

    @property
    def is_auto_approve(self) -> bool:
        """Only VERIFIED auto-approves, and only with a valid signature.

        CONTRACTS.md §1 Rule 1. This property is the single source of truth —
        no step may hardcode its own approval logic.
        """
        return self is Verdict.VERIFIED

    @property
    def requires_human_review(self) -> bool:
        """Outcomes that must reach an HR reviewer rather than a retry prompt."""
        return self in {
            Verdict.TAMPERED,
            Verdict.PROFILE_MISMATCH,
            Verdict.TEXT_MISMATCH,
            Verdict.DUPLICATE,
            Verdict.ERROR,
        }

    @property
    def allows_retry(self) -> bool:
        """Whether the employee may upload a different image."""
        return self is not Verdict.DUPLICATE and self is not Verdict.VERIFIED

    @property
    def is_auto_reject(self) -> bool:
        """Always False. CONTRACTS.md §1 Rule 2 — nothing is ever auto-rejected.

        Kept as an explicit property so the invariant is testable and any future
        attempt to introduce auto-rejection fails a unit test.
        """
        return False

    @property
    def decision_status(self) -> DecisionStatus:
        """What the employee should do next. See ``DecisionStatus``.

        ⚠ Written out verdict by verdict rather than derived from
          ``requires_human_review``/``allows_retry``, because those two overlap.
          Five verdicts are BOTH review-worthy and retry-allowed (§1), so any
          derivation would have to silently pick a winner. Naming each case
          keeps the choice visible and reviewable.

        ⛔ APPROVED here is necessary but NOT sufficient. The caller must still
           confirm ``proof.valid`` — same belt-and-braces as
           ``VerificationResult.is_auto_approve``, so that a bug in the rules
           engine cannot approve a document with no signature behind it.

        The reasoning, per verdict:

        * ``TAMPERED`` -> RETRY. The signature did not match, but the employee's
          only useful action is to upload clearer photos of the original — which
          is exactly what the message already says. HR is still alerted through
          ``requires_human_review``; this field is not that field.
        * ``ERROR`` -> RETRY. Our fault, not theirs. Retrying is the right advice
          and it must never read as a problem with their document.
        * ``PROFILE_MISMATCH`` / ``TEXT_MISMATCH`` / ``DUPLICATE`` -> REVIEW. A
          better photograph cannot change any of these. Telling the employee to
          try again would send them in a circle.
        * ``UNREADABLE`` / ``LEGACY_FORMAT`` / ``WRONG_DOCUMENT`` -> RETRY. All
          three are fixed by sending a different or better file.
        """
        if self is Verdict.VERIFIED:
            return DecisionStatus.APPROVED

        if self in {
            Verdict.PROFILE_MISMATCH,
            Verdict.TEXT_MISMATCH,
            Verdict.DUPLICATE,
        }:
            return DecisionStatus.REVIEW

        return DecisionStatus.RETRY


class CheckName(str, Enum):
    """Canonical names for every check emitted in ``checks[]``. See CONTRACTS.md §2."""

    FILE_VALIDATION = "file_validation"
    DOCUMENT_TYPE = "document_type"
    CAPTURE_QUALITY = "capture_quality"
    QR_LOCALISED = "qr_localised"
    QR_DECODED = "qr_decoded"
    PAYLOAD_PARSED = "payload_parsed"
    SIGNATURE_VERIFY = "signature_verify"
    SIDE_AGREEMENT = "side_agreement"
    OCR_CROSS_CHECK = "ocr_cross_check"
    PROFILE_NAME_MATCH = "profile_name_match"
    PROFILE_DOB_MATCH = "profile_dob_match"
    DUPLICATE_CHECK = "duplicate_check"

    @property
    def is_verdict_bearing(self) -> bool:
        """Only signature_verify can produce VERIFIED. Everything else is advisory
        or blocking. CONTRACTS.md §2 and §7.
        """
        return self is CheckName.SIGNATURE_VERIFY

    @property
    def is_ai_produced(self) -> bool:
        """AI-produced checks may never influence the verdict. CONTRACTS.md §7."""
        return self in {
            CheckName.DOCUMENT_TYPE,
            CheckName.CAPTURE_QUALITY,
            CheckName.QR_LOCALISED,
            CheckName.PROFILE_NAME_MATCH,
        }


class CheckResult(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    SKIP = "SKIP"  # feature disabled, model unavailable, or not applicable


class ErrorCode(str, Enum):
    """See CONTRACTS.md §3."""

    # Ingest
    FILE_TOO_LARGE = "FILE_TOO_LARGE"
    FILE_TOO_SMALL = "FILE_TOO_SMALL"
    UNSUPPORTED_MIME_TYPE = "UNSUPPORTED_MIME_TYPE"
    CORRUPT_IMAGE = "CORRUPT_IMAGE"
    DIMENSIONS_INVALID = "DIMENSIONS_INVALID"
    DECOMPRESSION_BOMB = "DECOMPRESSION_BOMB"
    MALWARE_DETECTED = "MALWARE_DETECTED"

    # PDF (CONTRACTS.md 2.0.0 — PDF admitted as input)
    #
    # ⚠ Password failure is split into two codes on purpose. e-Aadhaar files
    #   downloaded from UIDAI are encrypted, so "this file needs a password" and
    #   "that password was wrong" are both routine, and they need opposite
    #   things from the employee: supply one, versus correct the one supplied.
    #   A single code would force the UI to guess which had happened.
    PDF_PASSWORD_REQUIRED = "PDF_PASSWORD_REQUIRED"
    PDF_PASSWORD_INCORRECT = "PDF_PASSWORD_INCORRECT"

    # Decode
    QR_NOT_FOUND = "QR_NOT_FOUND"
    QR_DECODE_FAILED = "QR_DECODE_FAILED"

    # Parse
    PAYLOAD_MALFORMED = "PAYLOAD_MALFORMED"
    PAYLOAD_UNSUPPORTED_VERSION = "PAYLOAD_UNSUPPORTED_VERSION"
    PAYLOAD_LEGACY_UNSIGNED = "PAYLOAD_LEGACY_UNSIGNED"
    PAYLOAD_TRUNCATED = "PAYLOAD_TRUNCATED"

    # Crypto
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    TRUSTSTORE_EMPTY = "TRUSTSTORE_EMPTY"
    CERTIFICATE_EXPIRED = "CERTIFICATE_EXPIRED"
    CERTIFICATE_LOAD_FAILED = "CERTIFICATE_LOAD_FAILED"

    # Service
    STORAGE_FETCH_FAILED = "STORAGE_FETCH_FAILED"
    CALLBACK_FAILED = "CALLBACK_FAILED"
    TIMEOUT = "TIMEOUT"
    RATE_LIMITED = "RATE_LIMITED"
    INVALID_REQUEST = "INVALID_REQUEST"

    # AI — always non-fatal, degrade gracefully
    MODEL_LOAD_FAILED = "MODEL_LOAD_FAILED"
    MODEL_INFERENCE_FAILED = "MODEL_INFERENCE_FAILED"

    # General
    INTERNAL_ERROR = "INTERNAL_ERROR"

    @property
    def is_retryable(self) -> bool:
        return self in {
            ErrorCode.QR_NOT_FOUND,
            ErrorCode.QR_DECODE_FAILED,
            ErrorCode.CORRUPT_IMAGE,
            ErrorCode.STORAGE_FETCH_FAILED,
            ErrorCode.TIMEOUT,
            ErrorCode.RATE_LIMITED,
            ErrorCode.INTERNAL_ERROR,
        }

    @property
    def is_ai_degradation(self) -> bool:
        """AI errors never fail a verification — the pipeline continues without them."""
        return self in {ErrorCode.MODEL_LOAD_FAILED, ErrorCode.MODEL_INFERENCE_FAILED}


class DocType(str, Enum):
    """Output classes of the Step 13 document classifier."""

    AADHAAR_FRONT = "aadhaar_front"
    AADHAAR_BACK = "aadhaar_back"
    AADHAAR_PVC = "aadhaar_pvc"
    OTHER_ID = "other_id"
    NOT_A_DOCUMENT = "not_a_document"
    UNKNOWN = "unknown"  # classifier unavailable — pipeline continues

    @property
    def is_aadhaar(self) -> bool:
        return self in {
            DocType.AADHAAR_FRONT,
            DocType.AADHAAR_BACK,
            DocType.AADHAAR_PVC,
        }


class CardSide(str, Enum):
    """Which face of the Aadhaar card an image shows. See CONTRACTS.md §11.

    ⚠ The Secure QR may be on EITHER side. Placement varies by format: PVC cards
      carry it on the back, the classic printed letter often on the front, some
      e-Aadhaar printouts on both. Never assume "QR = back".
    """

    FRONT = "front"
    BACK = "back"


class CaptureMethod(str, Enum):
    CAMERA = "CAMERA"
    SCAN = "SCAN"
    UPLOAD = "UPLOAD"
    UNKNOWN = "UNKNOWN"


class Strictness(str, Enum):
    """Per-tenant policy. Affects review routing thresholds only — never the
    signature check, which is absolute.
    """

    LENIENT = "LENIENT"
    STANDARD = "STANDARD"
    STRICT = "STRICT"
