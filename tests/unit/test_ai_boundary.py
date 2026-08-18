"""The AI boundary — CONTRACTS.md section 7.

This is the most important architectural test in the project. It asserts, in code,
that no AI module can influence a verdict. If a future step imports an AI module
into the decision layer, CI fails here.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "avs"

#: Modules that decide. None of them may import from avs.ai.
DECISION_MODULES = ["rules", "crypto", "parser", "truststore"]


def _imports_of(pkg: Path) -> set[str]:
    found: set[str] = set()
    for py in pkg.rglob("*.py"):
        tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                found.update(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                found.add(node.module)
    return found


@pytest.mark.parametrize("module", DECISION_MODULES)
def test_decision_modules_never_import_ai(module: str) -> None:
    pkg = SRC / module
    if not pkg.exists():
        pytest.skip(f"{module} not yet implemented")
    offending = {i for i in _imports_of(pkg) if i.startswith("avs.ai")}
    assert not offending, (
        f"avs.{module} imports {offending}. CONTRACTS.md section 7 forbids any AI "
        f"module from reaching the decision layer."
    )


def test_ai_package_declares_the_rule() -> None:
    """The governing rule must stay documented where developers will see it."""
    text = (SRC / "ai" / "__init__.py").read_text(encoding="utf-8")
    assert "may produce or influence a Verdict" in text


def test_crypto_is_the_only_verdict_source() -> None:
    from avs.contracts import CheckName

    bearing = [c for c in CheckName if c.is_verdict_bearing]
    assert bearing == [CheckName.SIGNATURE_VERIFY]


# --------------------------------------------------------------------------- #
# The reverse direction — Step 12
#
# The tests above prove the decision layer never imports AI. That is one half.
# The other half is that AI never reaches INTO the decision layer, which is the
# more likely accident: the natural shape of "I just need a bit more context
# here" is an import, and a model that can call `crypto.verify` or read the
# rules engine has quietly become part of the decision.
# --------------------------------------------------------------------------- #

#: What a model is allowed to decide about. Never authenticity.
FORBIDDEN_TO_AI = ("avs.crypto", "avs.rules", "avs.truststore", "avs.parser")


def test_the_ai_layer_never_imports_the_decision_layer() -> None:
    """⛔ The wall, enforced from both sides.

    An AI module may look at pixels and suggest a preprocessing strategy. It may
    not look at a signature, a certificate, or a verdict — because a component
    that can see the decision is one refactor away from influencing it.
    """
    ai = SRC / "ai"
    if not ai.exists():
        pytest.skip("ai package not yet implemented")

    offending = {i for i in _imports_of(ai) if i.startswith(FORBIDDEN_TO_AI)}
    assert not offending, (
        f"avs.ai imports {offending}. CONTRACTS.md section 7: the AI layer works on "
        f"the INPUT side and the HUMAN-ASSIST side. It may never reach the decision."
    )


def test_the_model_runtime_exposes_no_verdict_shaped_result() -> None:
    """A type-level guard on the same rule.

    `InferenceOutcome` is what every model returns. If it ever gains a field an
    approval could be read from, the boundary has been crossed in a way no
    import check would catch.
    """
    from avs.ai.modelmgr import InferenceOutcome

    forbidden = {
        "verdict", "verified", "is_genuine", "authentic",
        "signature_valid", "approved", "valid",
    }  # fmt: skip
    fields = set(InferenceOutcome.__dataclass_fields__)

    assert not (fields & forbidden), (
        f"InferenceOutcome exposes {fields & forbidden} — a model must never "
        f"return something an approval can be read from."
    )


def test_every_ai_protocol_is_optional_in_the_pipeline() -> None:
    """⛔ CONTRACTS.md section 6: every AI Protocol may be absent at runtime.

    A pipeline that REQUIRED a model would make the accelerator a dependency —
    and a dependency that decides whether someone's document can be checked at
    all. The deterministic path must be complete on its own.
    """
    import inspect

    from avs.pipeline import DocumentVerifier

    signature = inspect.signature(DocumentVerifier.__init__)
    ai_params = [
        p
        for name, p in signature.parameters.items()
        if name in {"classifier", "quality", "localizer", "restorer"}
    ]

    for parameter in ai_params:
        assert parameter.default is not inspect.Parameter.empty, (
            f"DocumentVerifier requires {parameter.name!r}. Every AI component "
            f"must default to None so the pipeline runs without it."
        )
