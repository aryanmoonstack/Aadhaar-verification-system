"""avs.ai.modelmgr — model registry and inference runtime.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 12
Provides : ModelRegistry, ModelSpec, load_registry, ModelRunner, InferenceOutcome
Consumes : avs.contracts, onnxruntime (OPTIONAL)
Used by  : ai/classify (13), ai/quality (14), ai/localize (15), ai/restore (19)
Status   : COMPLETE

The foundation Steps 13-19 build on. It answers four questions once, so that
five later modules do not answer them five different ways:

    which file        registry, by name
    which version     recorded against every inference, for the audit trail
    is it OUR file    SHA-256 pinned, exactly as UIDAI certificates are pinned
    what if it breaks it degrades — always, on every path

⛔ NOTHING HERE MAY PRODUCE A VERDICT — CONTRACTS.md §7.
   If every model were replaced with a hostile one, the worst outcome is bad
   preprocessing advice and a re-upload prompt. Forging an approval still
   requires UIDAI's private key.
"""

from avs.ai.modelmgr.registry import (
    MANIFEST_NAME,
    ModelRegistry,
    ModelSpec,
    RegistryError,
    load_registry,
)
from avs.ai.modelmgr.runtime import (
    InferenceOutcome,
    InferenceSession,
    ModelRunner,
    onnxruntime_available,
)

__all__ = [
    "MANIFEST_NAME",
    "InferenceOutcome",
    "InferenceSession",
    "ModelRegistry",
    "ModelRunner",
    "ModelSpec",
    "RegistryError",
    "load_registry",
    "onnxruntime_available",
]
