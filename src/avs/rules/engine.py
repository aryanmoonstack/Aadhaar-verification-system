"""★ The verdict engine — Step 6.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 6
Provides : DeterministicVerdictEngine (implements avs.contracts.VerdictEngine)
Consumes : avs.contracts, avs.rules.messages
Used by  : avs.pipeline

⛔ THIS MODULE SEES ONLY ``CheckOutcome`` OBJECTS AND A ``SignatureProof``.

   Not model confidences. Not raw images. Not OCR text. Not similarity scores.
   That restriction is how CONTRACTS.md §7 — the AI boundary — is enforced
   structurally rather than by convention: the decision layer physically cannot
   consult an AI output, because none is in scope.

   ``tests/unit/test_ai_boundary.py`` parses this module's AST and fails CI if an
   ``avs.ai`` import ever appears.

THE TWO ABSOLUTE RULES, AS CODE
-------------------------------
**Rule 1** — ``VERIFIED`` requires ``proof.valid is True``. Nothing else can
produce it: no combination of passing checks, no threshold, no model.

**Rule 2** — nothing is ever auto-rejected. Every non-verified outcome routes to
a re-upload prompt or a human reviewer. The system never tells an employee they
committed fraud.

WHAT ``ERROR`` MEANS
--------------------
``ERROR`` is reserved for faults on **our** side — an empty trust store, an
expired certificate, an unexplained failure. It tells the employee to wait and
try again, which is only honest when the problem really is ours.

A rejected upload is not that. A file that failed validation, or an image with no
readable QR, is ``UNREADABLE`` — "retry with a different photo". Using ``ERROR``
there would tell someone to sit and wait for a fix that is never coming.

THE DISTINCTION THAT MATTERS MOST
---------------------------------
A signature that does not match means the *document* was altered → ``TAMPERED``.

An empty trust store, or one holding only expired certificates, means *we* are
misconfigured → ``ERROR``.

Both produce ``proof.valid is False``. Conflating them would report a genuine
Aadhaar as tampered because someone forgot to deploy a certificate — accusing an
employee of forgery over our own operational mistake. The engine therefore
branches on ``proof.error``, never on ``valid`` alone.
"""

from __future__ import annotations

from avs.contracts import (
    CheckName,
    CheckOutcome,
    CheckResult,
    ErrorCode,
    SignatureProof,
    Strictness,
    Verdict,
    VerificationResult,
)
from avs.rules.messages import message_for

__all__ = ["DeterministicVerdictEngine"]


#: Crypto errors that indicate OUR misconfiguration, not a problem with the
#: employee's document. These must never produce TAMPERED.
_SERVICE_FAULTS: frozenset[ErrorCode] = frozenset(
    {
        ErrorCode.TRUSTSTORE_EMPTY,
        ErrorCode.CERTIFICATE_EXPIRED,
        ErrorCode.CERTIFICATE_LOAD_FAILED,
    }
)

#: Advisory checks. A failure here routes to human review; it never approves and
#: never rejects. Ordered by severity — the first failure found wins.
_REVIEW_CHECKS: tuple[tuple[CheckName, Verdict], ...] = (
    (CheckName.DUPLICATE_CHECK, Verdict.DUPLICATE),
    (CheckName.SIDE_AGREEMENT, Verdict.TEXT_MISMATCH),
    (CheckName.OCR_CROSS_CHECK, Verdict.TEXT_MISMATCH),
    (CheckName.PROFILE_NAME_MATCH, Verdict.PROFILE_MISMATCH),
    (CheckName.PROFILE_DOB_MATCH, Verdict.PROFILE_MISMATCH),
)


class DeterministicVerdictEngine:
    """Maps evidence to one of the nine frozen verdicts. No scores, no thresholds."""

    def __init__(self, strictness: Strictness = Strictness.STANDARD) -> None:
        """
        Args:
            strictness: per-tenant policy. Affects **routing only** — whether a
                borderline case goes to a human or is approved. It can never
                change what the signature means, and no setting enables
                auto-rejection (CONTRACTS.md §1 Rule 2 is absolute).
        """
        self.strictness = strictness

    # ------------------------------------------------------------------ #

    def decide(
        self,
        checks: list[CheckOutcome],
        proof: SignatureProof | None,
    ) -> VerificationResult:
        """Produce the verdict skeleton.

        Returns a ``VerificationResult`` carrying the verdict, the checks, the
        proof and the employee-facing message. Extracted identity, address and
        per-side outcomes are attached by the pipeline afterwards — this module
        deliberately never sees them, so it cannot accidentally base a decision
        on demographic data.
        """
        by_name = {c.name: c for c in checks}
        verdict = self._verdict(by_name, proof)

        return VerificationResult(
            job_id="",  # set by the pipeline
            verdict=verdict,
            proof=proof,
            checks=list(checks),
            user_message=message_for(verdict, by_name),
        )

    # ------------------------------------------------------------------ #

    def _verdict(
        self,
        checks: dict[CheckName, CheckOutcome],
        proof: SignatureProof | None,
    ) -> Verdict:
        """The decision table. First match wins; order is the policy."""

        # ── 1. A valid signature. The only route to approval. ─────────────
        if proof is not None and proof.valid is True:
            for name, review_verdict in _REVIEW_CHECKS:
                outcome = checks.get(name)
                if outcome is not None and outcome.result is CheckResult.FAIL:
                    return review_verdict

            if self.strictness is Strictness.STRICT:
                # A stricter tenant treats "we could not check" as "a human
                # should". Still never a rejection — only a routing change.
                for name, review_verdict in _REVIEW_CHECKS:
                    outcome = checks.get(name)
                    if outcome is not None and outcome.result is CheckResult.WARN:
                        return review_verdict

            return Verdict.VERIFIED

        # ── 2. Our fault, not theirs. Must not read as forgery. ───────────
        if proof is not None and proof.error in _SERVICE_FAULTS:
            return Verdict.ERROR

        # ── 3. A pre-2018 card. Genuine, just unverifiable. ───────────────
        if self._failed_with(checks, CheckName.PAYLOAD_PARSED, ErrorCode.PAYLOAD_LEGACY_UNSIGNED):
            return Verdict.LEGACY_FORMAT
        if proof is not None and proof.error is ErrorCode.PAYLOAD_LEGACY_UNSIGNED:
            return Verdict.LEGACY_FORMAT

        # ── 4. The signature genuinely did not match. ─────────────────────
        if proof is not None and proof.error is ErrorCode.SIGNATURE_INVALID:
            return Verdict.TAMPERED

        # ── 5. Not an Aadhaar card at all. ────────────────────────────────
        if self._failed(checks, CheckName.DOCUMENT_TYPE):
            return Verdict.WRONG_DOCUMENT

        # ── 6. Nothing got past the security boundary. ────────────────────
        #
        # Checked BEFORE qr_decoded, deliberately. If no image was accepted we
        # never looked for a QR, so "we could not read the QR code" would be
        # untrue and would send the employee off to improve their lighting when
        # the real problem is the file itself.
        #
        # And UNREADABLE rather than ERROR: ERROR means WE are broken and the
        # employee should wait. A rejected upload is neither — it is a retry
        # with a different image, which is exactly what UNREADABLE means.
        if self._failed(checks, CheckName.FILE_VALIDATION):
            return Verdict.UNREADABLE

        # ── 7. No usable QR. ──────────────────────────────────────────────
        decoded = checks.get(CheckName.QR_DECODED)
        if decoded is not None and decoded.result is CheckResult.FAIL:
            # A QR was present but belonged to something else — the employee
            # most likely photographed the wrong document.
            if decoded.error is ErrorCode.QR_NOT_FOUND and "foreign" in (decoded.detail or ""):
                return Verdict.WRONG_DOCUMENT
            return Verdict.UNREADABLE

        # ── 8. Malformed payload that still reached us. ───────────────────
        if self._failed(checks, CheckName.PAYLOAD_PARSED):
            return Verdict.UNREADABLE

        # No evidence at all — we genuinely do not know what happened, which is
        # a fault on our side, not theirs.
        return Verdict.ERROR

    # ------------------------------------------------------------------ #

    @staticmethod
    def _failed(checks: dict[CheckName, CheckOutcome], name: CheckName) -> bool:
        outcome = checks.get(name)
        return outcome is not None and outcome.result is CheckResult.FAIL

    @staticmethod
    def _failed_with(
        checks: dict[CheckName, CheckOutcome],
        name: CheckName,
        code: ErrorCode,
    ) -> bool:
        outcome = checks.get(name)
        return outcome is not None and outcome.result is CheckResult.FAIL and outcome.error is code
