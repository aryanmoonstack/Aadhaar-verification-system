"""Module interfaces — the architectural seams. See CONTRACTS.md section 6.

⛔ FROZEN. Every module implements its Protocol here. This is the mechanism that
   lets a module written in Step 18 plug correctly into one written in Step 1,
   weeks apart, without either knowing the other's internals.

Two rules encoded structurally in this file:

1. Every AI Protocol is OPTIONAL at runtime. The pipeline accepts ``None`` for
   each and continues deterministically. AI is an accelerator, never a dependency.

2. Only ``SignatureVerifier`` produces a verdict-bearing result. Every other
   Protocol returns advisory data that ``VerdictEngine`` may use to route to human
   review — but never to approve. See CONTRACTS.md §7.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol, runtime_checkable

from avs.contracts.models import (
    AadhaarIdentity,
    CheckOutcome,
    DecodeResult,
    DocTypePrediction,
    ExpectedIdentity,
    ImageVariant,
    MatchOutcome,
    NameSimilarity,
    QrPayload,
    QrRegion,
    QualityScores,
    SignatureProof,
    TextSimilarity,
    ValidatedImage,
    VerificationResult,
)

__all__ = [
    "CertificateStore",
    "DocumentClassifier",
    "IdentityBinder",
    "ImageRestorer",
    "Ingestor",
    "NameMatcher",
    "PayloadParser",
    "PrivacyFilter",
    "QrDecoder",
    "QrLocalizer",
    "QualityAssessor",
    "SignatureVerifier",
    "TextCrossChecker",
    "VariantGenerator",
    "VerdictEngine",
]


# --------------------------------------------------------------------------- #
# Deterministic pipeline — always present
# --------------------------------------------------------------------------- #


@runtime_checkable
class Ingestor(Protocol):
    """``ingest/`` — Step 3. First security boundary."""

    def ingest(self, data: bytes, filename: str | None = None) -> ValidatedImage:
        """Validate and normalise raw upload bytes.

        Raises:
            IngestError: with an ErrorCode from the ingest family.
        """
        ...


@runtime_checkable
class VariantGenerator(Protocol):
    """``imaging/`` — Step 4.

    The ``quality`` parameter is the seam for Step 14: when the quality model is
    available it narrows the strategy set from ~40 variants to ~6. When it is
    ``None`` the full deterministic matrix is generated.

    The ``region`` parameter is the seam for Step 15: when the QR localiser has
    found the code, variants are generated from the cropped region rather than
    the whole photograph.

    Returns ``Iterable`` rather than ``list`` (contract 1.1.0) so implementations
    can yield lazily. A 12 MP photo expanded into ~40 encoded variants is several
    hundred megabytes, and the Step 5 cascade stops at the first success — so
    most of that work is never needed. Implementations SHOULD be lazy and SHOULD
    yield cheapest-first.
    """

    def generate(
        self,
        image: ValidatedImage,
        region: QrRegion | None = None,
        quality: QualityScores | None = None,
    ) -> Iterable[ImageVariant]: ...


@runtime_checkable
class QrDecoder(Protocol):
    """``qr/`` — Step 5. Decoder cascade.

    Accepts the lazy stream from ``VariantGenerator.generate`` (contract 1.2.0).

    Implementations MUST stop at the first successful decode. That is what makes
    the cheapest-first tier ordering in ``imaging/`` pay off — a good capture
    should cost one variant, not twenty-three.
    """

    def decode(self, variants: Iterable[ImageVariant]) -> DecodeResult: ...


@runtime_checkable
class PayloadParser(Protocol):
    """``parser/`` — Step 1.

    ⚠ Responsible for the security invariant in CONTRACTS.md §5:
      signed_bytes = payload[:-256], signature = payload[-256:]
    """

    def parse(self, raw_payload: str) -> QrPayload:
        """Unpack a decoded QR string into structured fields plus signature.

        Raises:
            ParseError: with an ErrorCode from the parse family.
        """
        ...


@runtime_checkable
class SignatureVerifier(Protocol):
    """``crypto/`` — Step 1. ★ THE ONLY VERDICT-BEARING COMPONENT ★

    ``SignatureProof.valid is True`` is the sole condition under which
    ``Verdict.VERIFIED`` may be produced. No AI, no heuristic, and no combination
    of other checks may substitute for it. See CONTRACTS.md §1 Rule 1.
    """

    def verify(self, payload: QrPayload) -> SignatureProof: ...


@runtime_checkable
class CertificateStore(Protocol):
    """``truststore/`` — Step 2. Multi-certificate, rotation-tolerant."""

    def certificates(self) -> list[object]:
        """All loaded UIDAI certificates. Verification tries each in turn."""
        ...

    def days_to_earliest_expiry(self) -> int | None:
        """For the 90-day expiry alert. ``None`` if the store is empty."""
        ...


@runtime_checkable
class VerdictEngine(Protocol):
    """``rules/`` — Step 6. Deterministic decision table.

    ⛔ Accepts ONLY ``CheckOutcome`` objects and a ``SignatureProof``. It has no
       access to raw model confidences — that restriction is how the AI boundary
       in CONTRACTS.md §7 is enforced structurally rather than by convention.
       ``tests/unit/test_ai_boundary.py`` asserts no avs.ai import reaches here.
    """

    def decide(
        self,
        checks: list[CheckOutcome],
        proof: SignatureProof | None,
    ) -> VerificationResult: ...


@runtime_checkable
class PrivacyFilter(Protocol):
    """``privacy/`` — Step 6. Data minimisation applied before anything leaves."""

    def apply(self, result: VerificationResult) -> VerificationResult:
        """Mask, hash, and strip. Must be the last step before serialisation."""
        ...


# --------------------------------------------------------------------------- #
# Advisory / review-side — may return None, never decides
# --------------------------------------------------------------------------- #


@runtime_checkable
class TextCrossChecker(Protocol):
    """``ocr/`` — Step 17. Catches a genuine QR pasted onto a forged card face.

    ⛔ Output routes to human review only. Can never approve or reject.
    """

    def cross_check(self, image: ValidatedImage, payload: QrPayload) -> TextSimilarity: ...


@runtime_checkable
class IdentityBinder(Protocol):
    """``matching/`` — Step 18. Name, DOB, and duplicate binding."""

    def bind(
        self,
        identity: AadhaarIdentity,
        expected: ExpectedIdentity,
        tenant_id: str,
    ) -> MatchOutcome: ...


# --------------------------------------------------------------------------- #
# AI Protocols — ALL OPTIONAL AT RUNTIME
#
# Every consumer must accept None and continue deterministically. If a model
# fails to load, the pipeline degrades; it does not fail. See CONTRACTS.md §7.
# --------------------------------------------------------------------------- #


@runtime_checkable
class DocumentClassifier(Protocol):
    """``ai/classify/`` — Step 13. OPTIONAL. Advisory only."""

    def classify(self, image: ValidatedImage) -> DocTypePrediction: ...


@runtime_checkable
class QualityAssessor(Protocol):
    """``ai/quality/`` — Step 14. OPTIONAL. Advisory only. Highest-ROI component."""

    def assess(self, image: ValidatedImage) -> QualityScores: ...


@runtime_checkable
class QrLocalizer(Protocol):
    """``ai/localize/`` — Step 15. OPTIONAL. Returns None when no QR is found."""

    def localize(self, image: ValidatedImage) -> QrRegion | None: ...


@runtime_checkable
class ImageRestorer(Protocol):
    """``ai/restore/`` — Step 19. OPTIONAL. Retry path only.

    Safe by construction: a restored image still has to pass the signature check.
    If restoration corrupts payload bytes the signature simply fails — it cannot
    manufacture an approval. See CONTRACTS.md §7.
    """

    def restore(self, image: ValidatedImage) -> ValidatedImage: ...


@runtime_checkable
class NameMatcher(Protocol):
    """``ai/namematch/`` — Step 18. OPTIONAL. Advisory only.

    Falls back to literal fuzzy matching when the model is unavailable.
    """

    def match(self, candidate: str, expected: str) -> NameSimilarity: ...
