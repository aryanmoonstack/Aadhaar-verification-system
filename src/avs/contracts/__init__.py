"""avs.contracts — the frozen interface layer.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 0
Provides : enums, domain models, and module Protocols for every other module
Consumes : nothing (this package must never import from another avs module)
Status   : FROZEN — see CONTRACTS.md

Import everything from here rather than reaching into submodules, so that a future
internal reorganisation cannot break consumers:

    from avs.contracts import Verdict, QrPayload, SignatureVerifier
"""

from avs.contracts.enums import (
    CaptureMethod,
    CardSide,
    CheckName,
    CheckResult,
    DecisionStatus,
    DocType,
    ErrorCode,
    Strictness,
    Verdict,
)
from avs.contracts.models import (
    AadhaarAddress,
    AadhaarIdentity,
    AiTrace,
    AvsError,
    AvsModel,
    CardSideOutcome,
    CheckOutcome,
    ClientHints,
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
    VerifyPolicy,
    VerifyRequest,
)
from avs.contracts.protocols import (
    CertificateStore,
    DocumentClassifier,
    IdentityBinder,
    ImageRestorer,
    Ingestor,
    NameMatcher,
    PayloadParser,
    PrivacyFilter,
    QrDecoder,
    QrLocalizer,
    QualityAssessor,
    SignatureVerifier,
    TextCrossChecker,
    VariantGenerator,
    VerdictEngine,
)

CONTRACT_VERSION = "2.0.0"
"""Bumped only when CONTRACTS.md changes. Consumers may assert against this."""

__all__ = [
    "CONTRACT_VERSION",
    "AadhaarAddress",
    "AadhaarIdentity",
    "AiTrace",
    "AvsError",
    # models
    "AvsModel",
    "CaptureMethod",
    "CardSide",
    "CardSideOutcome",
    "CertificateStore",
    "CheckName",
    "CheckOutcome",
    "CheckResult",
    "ClientHints",
    "DecodeResult",
    "DocType",
    "DocTypePrediction",
    "DocumentClassifier",
    "ErrorCode",
    "ExpectedIdentity",
    "IdentityBinder",
    "ImageRestorer",
    "ImageVariant",
    # protocols
    "Ingestor",
    "MatchOutcome",
    "NameMatcher",
    "NameSimilarity",
    "PayloadParser",
    "PrivacyFilter",
    "QrDecoder",
    "QrLocalizer",
    "QrPayload",
    "QrRegion",
    "QualityAssessor",
    "QualityScores",
    "SignatureProof",
    "SignatureVerifier",
    "Strictness",
    "TextCrossChecker",
    "TextSimilarity",
    "ValidatedImage",
    "VariantGenerator",
    # enums
    "DecisionStatus",
    "Verdict",
    "VerdictEngine",
    "VerificationResult",
    "VerifyPolicy",
    "VerifyRequest",
]
