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
    ErrorCode,
    ExpectedIdentity,
    QrPayload,
    SignatureProof,
    Strictness,
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
        return self.privacy.apply(result)

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
        decoded = bounded.decode(self.generator.generate(image))
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
