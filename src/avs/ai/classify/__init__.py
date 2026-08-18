"""avs.ai.classify — Document type classification (Step 13).

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 13
Provides : build_classifier(), HeuristicClassifier, OnnxDocumentClassifier,
           DocumentFeatures, extract_features(), CLASS_ORDER, MODEL_NAME
Consumes : avs.ai.modelmgr, avs.imaging.ops, avs.contracts
Used by  : avs.pipeline (optional parameter), avs.cli
Status   : COMPLETE

WHAT THIS BUYS THE EMPLOYEE
---------------------------
Today, someone who uploads the wrong thing entirely — a PAN card, a payslip, an
accidental photo of the floor — gets::

    "We could not read the QR code. Please photograph both sides of your
     Aadhaar card in good light, holding the card flat and filling the frame."

That message sends them off to fix their lighting. They retake the photo in
better light. It fails again, for the same reason it failed the first time, and
they have no way to discover why. The instruction is not merely unhelpful, it is
actively misleading — it names a cause that is not the cause.

This module exists to notice that case and say something true instead.

⛔ WHAT IT MAY AND MAY NOT DO

   May: change the wording of a failure that has ALREADY happened.
   May not: cause a failure, change a verdict, or influence an approval.

   The classifier is consulted only after the deterministic path has finished
   and failed. If the QR decoded and the signature verified, the verdict is
   VERIFIED and nothing here is even asked. That is not a promise in a comment;
   ``tests/unit/test_classify_never_changes_verdict.py`` runs the whole pipeline
   against every class this module can emit and asserts the verdict is
   byte-identical to the run without it.

TWO BACKENDS, ONE CONTRACT
--------------------------
``OnnxDocumentClassifier`` — the full five-class model, when weights exist.
                             THE production backend.
``HeuristicClassifier``    — ⛔ RETIRED FROM PRODUCTION. Kept as the reference
                             implementation and for diagnostics. Caught 0 of 19
                             real wrong-uploads; see ``heuristic.py``.

``build_classifier()`` returns the model if one is pinned, otherwise ``None``.
``None`` is a normal, expected answer today — no weights ship yet.

⚠ WHAT THIS STEP ACTUALLY DELIVERED

  Not a working classifier. It delivered the SEAM for one — the feature
  extractor, the ONNX adapter, the pipeline wiring, and the runtime proof that
  no classifier output can move a verdict — plus the measurement infrastructure
  that showed the interim heuristic does not work. Knowing that now, from real
  data, is worth more than shipping something that quietly did nothing.
"""

from __future__ import annotations

from avs.ai.classify.features import DocumentFeatures, extract_features
from avs.ai.classify.heuristic import HeuristicClassifier
from avs.ai.classify.onnx import CLASS_ORDER, MODEL_NAME, OnnxDocumentClassifier
from avs.contracts import DocumentClassifier
from avs.logging import get_logger

__all__ = [
    "CLASS_ORDER",
    "MODEL_NAME",
    "DocumentFeatures",
    "HeuristicClassifier",
    "OnnxDocumentClassifier",
    "build_classifier",
    "extract_features",
]

log = get_logger(__name__)


def build_classifier(
    model_dir: str | None = "models",
    *,
    allow_heuristic: bool = False,
) -> DocumentClassifier | None:
    """The classifier to use, or None if classification is unavailable.

    ⛔ ``allow_heuristic`` DEFAULTS TO FALSE — RETIRED BY MEASUREMENT.

       It defaulted to True when Step 13 shipped. Measured against 19 real
       wrong-upload images (screenshots, UI mockups, keyboards, a desk, a
       sunset, a face), the heuristic caught **0 of 19**. See
       ``heuristic.py`` for the full numbers and why tuning cannot fix it.

       So in production this returns a classifier only when a trained model
       exists, and ``None`` otherwise — and ``None`` means the pipeline behaves
       exactly as it did before Step 13, which is correct.

       The heuristic is NOT deleted. It remains as the reference implementation,
       it is still exercised by its tests, and diagnostic tooling
       (``avs classify``, ``scripts/collect_classifier_features.py``) opts into
       it explicitly. What changed is that it no longer runs for real employees,
       because on real data it would never have said anything.

    ⛔ Never raises. A caller deciding whether to classify should not have to
       wrap construction in try/except — forgetting to is how an optional
       component quietly becomes required (D120).
    """
    try:
        from avs.ai.modelmgr import ModelRunner, load_registry

        registry = load_registry(model_dir or "models")
        if registry.get(MODEL_NAME) is not None and registry.path_for(MODEL_NAME) is not None:
            log.info("ai.classify.backend", backend="onnx", model=MODEL_NAME)
            return OnnxDocumentClassifier(ModelRunner(registry))
    except BaseException as exc:
        # A malformed models.json must not stop classification, let alone
        # verification — fall through to the heuristic.
        log.warning("ai.classify.registry_unavailable", error=type(exc).__name__)

    if allow_heuristic:
        log.info("ai.classify.backend", backend="heuristic")
        return HeuristicClassifier()

    return None
