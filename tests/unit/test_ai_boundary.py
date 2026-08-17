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
