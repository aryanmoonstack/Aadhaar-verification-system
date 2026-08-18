"""Document verification pipeline — Step 6.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 6
Provides : DocumentVerifier, SideInput
Consumes : avs.ingest, avs.imaging, avs.qr, avs.parser, avs.crypto,
           avs.truststore, avs.rules, avs.privacy
Used by  : avs.api (Step 7), CLI

This is the orchestrator. Every module built in Steps 0-5 is per-*image*; this
one assembles them into a per-*document* verdict.

    front.jpg ─┐
               ├─► ingest → preprocess → decode ─┐
    back.jpg  ─┘                                  │
                                                  ▼
                                   parse → ★ verify signature ★
                                                  │
                                                  ▼
                                        rules → privacy → verdict

TWO-SIDED ASSEMBLY (CONTRACTS.md §11)
-------------------------------------
Both sides are uploaded and processed. The Secure QR may be on either one —
placement varies by card format, so the pipeline tries both and takes whichever
yields a payload rather than assuming "QR = back".

The signature covers the QR payload only, never the printed card face. That is
precisely why both sides are collected: a genuine back paired with a forged front
would otherwise verify perfectly. Step 17's OCR cross-check is what will close
that, and it needs the second image to exist.

If one side is unreadable but the other's QR verifies, the verdict is still
``VERIFIED`` under ``STANDARD`` strictness. The signature is cryptographic proof;
it does not become less true because a second photograph was blurry. ``STRICT``
tenants route that case to a human instead. No policy enables auto-rejection.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass

from avs.contracts import (
    CardSide,
    CardSideOutcome,
    CheckName,
    CheckOutcome,
    CheckResult,
    DocType,
    DocTypePrediction,
    DocumentClassifier,
    ErrorCode,
    ExpectedIdentity,
    QrPayload,
    QualityAssessor,
    QualityScores,
    SignatureProof,
    Strictness,
    ValidatedImage,
    Verdict,
    VerificationResult,
)
from avs.crypto import SecureQrVerifier
from avs.imaging import PreprocessingVariantGenerator
from avs.ingest import ImageIngestor, IngestError
from avs.parser import ParseError, SecureQrParser
from avs.privacy import DataMinimisingFilter
from avs.qr import PayloadKind, QrDecoderCascade, classify_payload
from avs.rules import DeterministicVerdictEngine

__all__ = ["DocumentVerifier", "SideInput"]


@dataclass(frozen=True, slots=True)
class SideInput:
    """One uploaded image plus which face of the card it claims to be.

    The ``side`` label is metadata from the upload form — it says which slot the
    employee used, not which face the image actually shows. Nothing in the
    pipeline trusts it for decoding; it is used only for reporting and guidance.
    """

    side: CardSide
    data: bytes
    filename: str | None = None


@dataclass(frozen=True, slots=True)
class _SideResult:
    """Internal: what one side produced."""

    outcome: CardSideOutcome
    payload_text: str | None

    image: ValidatedImage | None = None
    """The ingested image, carried so Step 13 can classify without ingesting a
    second time.

    ⚠ Ingest is not free — it sniffs the format, decodes, normalises and may run
      a virus scan. Doing all of that twice for a cosmetic message would be
      wasteful, and re-ingesting could also FAIL the second time under memory
      pressure, losing the refinement for no reason.

    ⛔ In-memory only, for the life of one `verify()` call. It is never written
       anywhere — `tests/unit/test_statelessness.py` fails the build if image
       bytes reach disk."""

    quality: QualityScores | None = None
    """Step 14 scores, computed once during processing and reused for the
    message. Measuring twice would double the cost for an identical answer."""

    quality_problems: tuple[str, ...] = ()
    """Which named problems the assessor found — 'blurry', 'too_dark', and so
    on. Captured at assessment time so the failure message needs no second pass
    over the pixels."""


#: How sure the classifier must be before its wording is used at all.
#:
#: ⚠ High on purpose. The only thing at stake is which sentence an employee
#:   reads after a failure they are already having, so a confidently wrong
#:   instruction is worse than the generic one — it sends them off to fix the
#:   wrong problem, and unlike the generic message it sounds authoritative.
MIN_REFINEMENT_CONFIDENCE = 0.75

#: ⛔ The word "fake" appears nowhere here and must never appear in any
#:    employee-facing string. A genuine card photographed badly is
#:    indistinguishable from a forgery to any automated check — which is exactly
#:    why no automated check may call it one. CONTRACTS.md §1.
_NOT_A_DOCUMENT_MESSAGE = (
    "These photos do not appear to show a document. Please upload clear photos "
    "of the front and back of your Aadhaar card."
)

_OTHER_ID_MESSAGE = (
    "This looks like a different document. Please upload photos of the front "
    "and back of your Aadhaar card."
)


def _message_for_prediction(predictions: list[DocTypePrediction]) -> str | None:
    """The replacement message, or None to keep the deterministic one.

    ⚠ Requires unanimity. One clear photo of a card plus one photo of a thumb is
      a capture problem, and "retake in good light" is then the right advice.
      Saying "this is not a document" there would be both wrong and insulting.
    """
    if not predictions:
        return None

    confident = [p for p in predictions if p.confidence >= MIN_REFINEMENT_CONFIDENCE]
    if len(confident) != len(predictions):
        return None

    kinds = {p.doc_type for p in confident}
    if kinds == {DocType.NOT_A_DOCUMENT}:
        return _NOT_A_DOCUMENT_MESSAGE
    if kinds == {DocType.OTHER_ID}:
        return _OTHER_ID_MESSAGE

    # Mixed, UNKNOWN, or an Aadhaar class — the classifier agrees it is a card,
    # so the capture advice already in place is the correct advice.
    return None


def _advisor_name(advisor: object) -> str:
    """The name recorded in `AiTrace`.

    ⚠ Was `_classifier_name`, which returned "NoneType" when no classifier was
      configured — and none is, by default, since the classifier was retired in
      D135. "Which model produced this?" is the first question asked when a
      result looks wrong, and "NoneType" cannot answer it.
    """
    return str(getattr(advisor, "name", type(advisor).__name__))


#: Step 14 problem code -> what the employee is told.
#:
#: ⛔ ORDERED BY MEASURED COVERAGE, not by intuition. Across 27 real captures run
#:    through the actual decoder: sharpness explains 68% of failures, brightness
#:    a further 11% (79% combined), and QR size adds ZERO on top of those. The
#:    first matching entry wins, so the most useful advice is given first.
#:
#: ⛔ The word "fake" appears nowhere and must never appear. A genuine card
#:    photographed badly is indistinguishable from a forgery to any automated
#:    check — which is exactly why no automated check may call it one.
#:    CONTRACTS.md §1.
_QUALITY_MESSAGES: tuple[tuple[str, str], ...] = (
    (
        "blurry",
        "The photo is too blurry to read the code. Rest the card on a table, "
        "hold the phone steady, and tap the screen to focus before taking it.",
    ),
    (
        "too_dark",
        "The photo is too dark to read the code. Please retake it somewhere "
        "brighter — near a window works well, but avoid direct sunlight.",
    ),
    (
        "code_too_small",
        "The code on the card is too small to read. Please move closer so the "
        "card fills most of the frame.",
    ),
    (
        "code_at_edge",
        "Part of the code is cut off at the edge of the photo. Please retake it "
        "with the whole card inside the frame.",
    ),
    (
        "no_code_visible",
        "We could not find the code on either photo. Please make sure you are "
        "photographing your Aadhaar card, with the whole card in the frame.",
    ),
)


def _message_for_quality(problems: list[list[str]]) -> str | None:
    """The replacement message, or None to keep the deterministic one.

    ⚠ Requires the problem to be present on EVERY side that was assessed. One
      clear photo and one blurry one is a single-photo problem; telling the
      person "the photo is too blurry" when one of them was fine sends them to
      retake both, and is wrong about the good one.
    """
    if not problems or any(not found for found in problems):
        return None

    shared = [code for code, _ in _QUALITY_MESSAGES if all(code in f for f in problems)]
    if not shared:
        return None

    # ⛔ DARKNESS OUTRANKS BLUR WHEN BOTH FIRE — measured, not assumed.
    #
    #    Laplacian variance scales with CONTRAST, so a perfectly focused photo
    #    taken in the dark measures as blurry. Measured on one image at
    #    decreasing exposure, focus untouched throughout::
    #
    #        brightness x1.00  ->  sharpness 1315
    #        brightness x0.35  ->  sharpness  155
    #        brightness x0.12  ->  sharpness   22
    #
    #    So darkness CAUSES the low sharpness reading. Saying "hold steadier"
    #    to someone whose real problem is a dim room sends them to fix the wrong
    #    thing, and they will fail again identically. More light fixes both.
    if "too_dark" in shared and "blurry" in shared:
        shared.remove("blurry")

    first = shared[0]
    return next(message for code, message in _QUALITY_MESSAGES if code == first)


class DocumentVerifier:
    """Verifies an Aadhaar document from its two card faces."""

    def __init__(
        self,
        verifier: SecureQrVerifier,
        privacy: DataMinimisingFilter,
        *,
        ingestor: ImageIngestor | None = None,
        generator: PreprocessingVariantGenerator | None = None,
        cascade: QrDecoderCascade | None = None,
        parser: SecureQrParser | None = None,
        classifier: DocumentClassifier | None = None,
        quality: QualityAssessor | None = None,
        strictness: Strictness = Strictness.STANDARD,
        time_budget_seconds: float = 12.0,
    ) -> None:
        """
        Args:
            time_budget_seconds: wall-clock budget for the WHOLE document,
                shared across both sides.

                This is not a nicety. Measured in Step 5: a decodable image costs
                ~250 ms, an undecodable one burns the full variant matrix at
                ~4.3 s. Two unreadable sides is therefore ~9 s of CPU spent
                proving a negative — and unbounded, that is one employee's bad
                photo holding a worker while everyone else queues behind them.

                Budgeting the document rather than each side matters: if the
                front burns most of it, the back must still get its turn with
                whatever remains, because the back is usually where the QR is.
        """
        self.ingestor = ingestor or ImageIngestor()
        self.generator = generator or PreprocessingVariantGenerator()
        self.cascade = cascade or QrDecoderCascade()
        self.parser = parser or SecureQrParser()
        self.verifier = verifier
        self.privacy = privacy
        self.rules = DeterministicVerdictEngine(strictness=strictness)
        self.strictness = strictness
        self.time_budget_seconds = time_budget_seconds

        #: Step 13. OPTIONAL — defaults to None and the pipeline is complete
        #: without it. ⛔ Consulted ONLY after the deterministic path has already
        #: failed, and only ever to reword the message. See `_refine_message`.
        self.classifier = classifier

        #: Step 14. OPTIONAL. Does exactly two things, both safe by construction:
        #:
        #:   1. REORDERS the preprocessing variants so the likeliest runs first.
        #:      ⛔ Never removes one — `select_strategies` returns the full
        #:         matrix regardless, so this cannot cause a failure that would
        #:         not otherwise have happened (D141).
        #:   2. Names WHAT is wrong after a failure, so "we could not read the QR
        #:      code" becomes "the photo is too blurry".
        #:
        #: Measured on 27 real captures: sharpness + brightness explain 79% of
        #: failures with zero false alarms.
        self.quality = quality

    # ------------------------------------------------------------------ #

    def verify(
        self,
        sides: list[SideInput],
        *,
        job_id: str | None = None,
        expected: ExpectedIdentity | None = None,
    ) -> VerificationResult:
        """Verify a document. Never raises — every failure becomes a verdict.

        A verification that threw an exception would leave the employee with no
        message and HR with no record. Every path here produces a result.
        """
        started = time.perf_counter()
        job = job_id or str(uuid.uuid4())
        deadline = started + self.time_budget_seconds

        results = self._process_sides(sides, deadline)
        checks = self._build_checks(results)

        payload, proof, parse_error = self._verify_payloads(results, checks)
        checks.extend(self._payload_checks(payload, proof, parse_error))

        result = self.rules.decide(checks, proof)

        result = result.model_copy(
            update={
                "job_id": job,
                "sides": [r.outcome for r in results],
                "identity": payload.identity if payload else None,
                "address": payload.address if payload else None,
                "processing_ms": int((time.perf_counter() - started) * 1000),
            }
        )

        # ⛔ Step 13. Runs LAST, on a verdict that is already final. It may
        #    return a result whose `user_message` differs; it may never return
        #    one whose `verdict` differs — enforced by `_refine_message` and
        #    asserted for every possible prediction in
        #    tests/unit/test_classify_never_changes_verdict.py.
        result = self._refine_message(result, results)

        return self.privacy.apply(result)

    # ------------------------------------------------------------------ #
    # Step 13 — message refinement. NOT a decision.
    # ------------------------------------------------------------------ #

    def _refine_message(
        self, result: VerificationResult, results: list[_SideResult]
    ) -> VerificationResult:
        """Say something true when the standard message would mislead.

        THE PROBLEM THIS SOLVES
        -----------------------
        Someone uploads a payslip, a PAN card, or an accidental photo of the
        floor. The QR is not found, so the verdict is UNREADABLE and they are
        told::

            "We could not read the QR code. Please photograph both sides of
             your Aadhaar card in good light..."

        They retake it in better light. It fails again, identically, and nothing
        in the message could ever have told them why. The instruction does not
        merely fail to help — it names a cause that is not the cause.

        ⛔ WHY THIS CANNOT AFFECT A VERDICT

        Three independent reasons, any one of which would be sufficient:

        1. It runs after ``rules.decide()`` has returned. The verdict exists
           before this method is called.
        2. It only ever writes ``user_message`` and ``ai_trace`` — never
           ``verdict``, ``proof``, ``checks`` or ``error``.
        3. It returns early on anything other than UNREADABLE. A VERIFIED
           document is never even classified, so no model output can exist that
           would have to be ignored.

        ⚠ Deliberately conservative: EVERY side must independently look like a
          non-document. One good photo of a card and one photo of a thumb is a
          capture problem, not a wrong-document problem, and the two need
          opposite advice.
        """
        # ⛔ Either advisor is enough. This used to read `if self.classifier is
        #    None`, written when the classifier was the only advisor. Step 14
        #    added quality, and with no classifier configured — which is now the
        #    DEFAULT, since the classifier was retired in D135 — that guard
        #    returned before quality ever ran, so the measured component was
        #    silently dead in the normal configuration.
        if (self.classifier is None and self.quality is None) or not results:
            return result

        # Only UNREADABLE. TAMPERED means a QR decoded and parsed — the document
        # IS an Aadhaar and classification adds nothing. ERROR is our fault, not
        # the employee's, and VERIFIED needs no help.
        if result.verdict is not Verdict.UNREADABLE:
            return result

        started = time.perf_counter()
        predictions: list[DocTypePrediction] = []
        degraded: list[str] = []

        for side_result in results if self.classifier is not None else []:
            if side_result.image is None:
                # Ingest failed for this side. There is nothing to look at, and
                # the FILE_VALIDATION message already says something true.
                continue
            try:
                predictions.append(self.classifier.classify(side_result.image))
            except BaseException as exc:
                # ⛔ Broad by design. This is cosmetic work running after a
                #    verdict is settled; it must never be the reason a result
                #    fails to reach the employee (D120).
                degraded.append(type(exc).__name__)

        elapsed_ms = int((time.perf_counter() - started) * 1000)

        # ⛔ QUALITY FIRST — it is the measured component.
        #
        #    Step 14's thresholds come from 27 real captures paired with actual
        #    decode outcomes: 79% of failures explained, zero false alarms. The
        #    Step 13 classifier caught 0 of 19 real wrong-uploads and is retired
        #    (D135), so when both have something to say, quality wins.
        quality_message = _message_for_quality(
            [list(side.quality_problems) for side in results if side.image is not None]
        )

        if not predictions and quality_message is None:
            return result

        used = [
            _advisor_name(advisor)
            for advisor in (self.quality, self.classifier)
            if advisor is not None
        ]
        trace = result.ai_trace.model_copy(
            update={
                "models_used": [*result.ai_trace.models_used, *used],
                "total_ai_ms": result.ai_trace.total_ai_ms + elapsed_ms,
                "degraded": [*result.ai_trace.degraded, *degraded],
            }
        )

        # Quality outranks classification — see the note above.
        message = quality_message or _message_for_prediction(predictions)
        update: dict[str, object] = {"ai_trace": trace}
        if message is not None:
            update["user_message"] = message

        # ⛔ `update` contains only `ai_trace` and possibly `user_message`.
        #    Nothing else can be reached from here.
        return result.model_copy(update=update)

    # ------------------------------------------------------------------ #
    # Per-side processing — Steps 3, 4, 5 in sequence
    # ------------------------------------------------------------------ #

    def _process_sides(self, sides: list[SideInput], deadline: float) -> list[_SideResult]:
        """Process each side with a FAIR share of the remaining budget.

        ⚠ Not first-come-first-served. Measured: a side with no Aadhaar QR burns
          the full variant matrix — about 8 seconds — proving a negative. Handing
          the first side the whole budget lets one bad photo starve a perfectly
          good one, and since the QR is usually on the *second* side people
          upload, that is the common case rather than the rare one.

          So each remaining side gets ``remaining / sides_left``. A side that
          finishes fast hands its unused time back to the others, which means a
          good capture still gets the full budget when its partner failed early.
        """
        results: list[_SideResult] = []
        for index, side in enumerate(sides):
            remaining_sides = len(sides) - index
            remaining_time = max(0.0, deadline - time.perf_counter())
            share = remaining_time / remaining_sides
            results.append(self._process_side(side, time.perf_counter() + share))
        return results

    def _assess(self, image: ValidatedImage) -> tuple[QualityScores | None, tuple[str, ...]]:
        """Score a capture once, returning the scores and the named problems.

        Both come from a single pass: the scores reorder the variant matrix, the
        problem names supply the failure message. Splitting them across two calls
        would measure identical pixels twice.

        ⛔ Never raises. An advisory component that can throw is a dependency
           with extra steps (D120); a failed assessment simply means the
           deterministic variant order stands and the generic message is used.
        """
        if self.quality is None:
            return None, ()

        # ⚠ `assess_detailed` is an OPTIONAL enrichment, not part of the
        #   `QualityAssessor` Protocol. A third-party assessor implementing only
        #   `assess()` still reorders the variants correctly; it just cannot name
        #   the problem, and the deterministic message stands.
        detailed = getattr(self.quality, "assess_detailed", None)
        if callable(detailed):
            try:
                scores, problems = detailed(image)
                return scores, tuple(problems)
            except BaseException:
                return None, ()

        try:
            return self.quality.assess(image), ()
        except BaseException:
            return None, ()

    def _process_side(self, side: SideInput, deadline: float) -> _SideResult:
        started = time.perf_counter()

        try:
            image = self.ingestor.ingest(side.data, filename=side.filename)
        except IngestError as exc:
            return _SideResult(
                CardSideOutcome(
                    side=side.side,
                    ingested=False,
                    error=exc.code,
                    processing_ms=int((time.perf_counter() - started) * 1000),
                ),
                None,
            )

        # Whatever budget the previous side left behind. Never negative — a side
        # that gets no time still tries its first (cheapest) variant, because
        # that is where most captures decode anyway.
        remaining = max(0.05, deadline - time.perf_counter())
        bounded = QrDecoderCascade(
            decoders=self.cascade.decoders,  # reuse — constructing detectors is not free
            max_variants=self.cascade.max_variants,
            time_budget_seconds=remaining,
        )

        # ⛔ Step 14. Scores REORDER the variant matrix; they never shrink it —
        #    `select_strategies` returns every strategy regardless (D141). So a
        #    wrong assessment costs some wasted ordering, never a lost decode.
        #
        # ⚠ Assessed once and carried on the result. The same numbers name the
        #   problem in the failure message later; measuring twice would double
        #   the cost for an identical answer.
        scores, problems = self._assess(image)
        decoded = bounded.decode(self.generator.generate(image, quality=scores))
        elapsed = int((time.perf_counter() - started) * 1000)

        kind = classify_payload(decoded.raw_payload) if decoded.raw_payload else None

        return _SideResult(
            CardSideOutcome(
                side=side.side,
                ingested=True,
                decoded=decoded.success,
                payload_kind=kind.value if kind else None,
                decoder=decoded.decoder,
                strategy=decoded.strategy,
                variants_tried=decoded.attempts,
                foreign_qr_found=decoded.foreign_qr_found,
                error=None if decoded.success else ErrorCode.QR_NOT_FOUND,
                processing_ms=elapsed,
            ),
            decoded.raw_payload,
            image=image,
            quality=scores,
            quality_problems=problems,
        )

    # ------------------------------------------------------------------ #
    # Evidence assembly
    # ------------------------------------------------------------------ #

    def _build_checks(self, results: list[_SideResult]) -> list[CheckOutcome]:
        checks: list[CheckOutcome] = []

        ingested = [r for r in results if r.outcome.ingested]
        if not ingested:
            codes = {r.outcome.error for r in results if r.outcome.error}
            checks.append(
                CheckOutcome(
                    name=CheckName.FILE_VALIDATION,
                    result=CheckResult.FAIL,
                    detail="no side passed validation",
                    error=next(iter(codes), ErrorCode.CORRUPT_IMAGE),
                )
            )
        else:
            failed = [r.outcome.side.value for r in results if not r.outcome.ingested]
            checks.append(
                CheckOutcome(
                    name=CheckName.FILE_VALIDATION,
                    result=CheckResult.WARN if failed else CheckResult.PASS,
                    detail=f"rejected: {', '.join(failed)}" if failed else None,
                )
            )

        decoded = [r for r in results if r.payload_text]
        if decoded:
            winner = decoded[0].outcome
            checks.append(
                CheckOutcome(
                    name=CheckName.QR_DECODED,
                    result=CheckResult.PASS,
                    detail=f"{winner.side.value} via {winner.decoder}",
                    duration_ms=winner.processing_ms,
                )
            )
        else:
            missing = ", ".join(r.outcome.side.value for r in results)
            foreign = any(r.outcome.foreign_qr_found for r in results)
            checks.append(
                CheckOutcome(
                    name=CheckName.QR_DECODED,
                    result=CheckResult.FAIL,
                    detail=("foreign QR only; " if foreign else "") + f"no QR on: {missing}",
                    error=ErrorCode.QR_NOT_FOUND,
                )
            )

        checks.append(self._side_agreement(results))
        return checks

    @staticmethod
    def _side_agreement(results: list[_SideResult]) -> CheckOutcome:
        """Do the two faces belong to the same card?

        Two different Secure QR payloads on one document means the front and back
        came from different cards — which is exactly the assembled-forgery case
        worth a human look. Routes to review, never rejects.
        """
        payloads = {r.payload_text for r in results if r.payload_text}

        if len(payloads) > 1:
            return CheckOutcome(
                name=CheckName.SIDE_AGREEMENT,
                result=CheckResult.FAIL,
                detail="the two sides carry different Secure QR payloads",
            )
        if len(payloads) == 1 and sum(1 for r in results if r.payload_text) > 1:
            return CheckOutcome(
                name=CheckName.SIDE_AGREEMENT,
                result=CheckResult.PASS,
                detail="both sides carry the same payload",
            )
        # Only one side had a QR — normal for a PVC card, and nothing to compare.
        return CheckOutcome(
            name=CheckName.SIDE_AGREEMENT,
            result=CheckResult.SKIP,
            detail="only one side carried a Secure QR",
        )

    # ------------------------------------------------------------------ #
    # Parse and verify — the security decision
    # ------------------------------------------------------------------ #

    def _verify_payloads(
        self,
        results: list[_SideResult],
        checks: list[CheckOutcome],
    ) -> tuple[QrPayload | None, SignatureProof | None, ErrorCode | None]:
        """Try every decoded payload; the first that verifies wins.

        A Secure QR is preferred over a legacy one — a card carrying both should
        be verified, not merely identified as old.
        """
        candidates = [r.payload_text for r in results if r.payload_text]
        candidates.sort(key=lambda text: classify_payload(text) is not PayloadKind.SECURE_QR)

        first_payload: QrPayload | None = None
        first_proof: SignatureProof | None = None
        parse_error: ErrorCode | None = None

        for text in candidates:
            try:
                payload = self.parser.parse(text)
            except ParseError as exc:
                parse_error = parse_error or exc.code
                continue

            proof = self.verifier.verify(payload)
            if proof.valid:
                return payload, proof, None

            if first_payload is None:
                first_payload, first_proof = payload, proof

        return first_payload, first_proof, parse_error

    @staticmethod
    def _payload_checks(
        payload: QrPayload | None,
        proof: SignatureProof | None,
        parse_error: ErrorCode | None,
    ) -> list[CheckOutcome]:
        checks: list[CheckOutcome] = []

        if payload is not None:
            checks.append(CheckOutcome(name=CheckName.PAYLOAD_PARSED, result=CheckResult.PASS))
        elif parse_error is not None:
            checks.append(
                CheckOutcome(
                    name=CheckName.PAYLOAD_PARSED,
                    result=CheckResult.FAIL,
                    error=parse_error,
                    detail="payload could not be unpacked",
                )
            )

        if proof is not None:
            checks.append(
                CheckOutcome(
                    name=CheckName.SIGNATURE_VERIFY,
                    result=CheckResult.PASS if proof.valid else CheckResult.FAIL,
                    error=proof.error,
                    detail=(
                        f"certificate {proof.certificate_serial[:16]}"
                        if proof.valid and proof.certificate_serial
                        else None
                    ),
                )
            )

        return checks

    # ------------------------------------------------------------------ #

    @property
    def is_ready(self) -> bool:
        """Can this pipeline actually approve anything?

        False when the trust store is empty — every genuine document would come
        back unverifiable. Step 7's readiness probe uses this.
        """
        return self.verifier.has_certificates
