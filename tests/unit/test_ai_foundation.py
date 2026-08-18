"""Model registry and inference runtime — Step 12.

⛔ THE PROPERTY EVERY TEST HERE DEFENDS

   **A model must never be able to fail a verification.**

   Not by being absent, not by being corrupt, not by throwing, not by hanging,
   not by returning nonsense. Every one of those is exercised below, and every
   one must end in "carry on deterministically".

   This is what makes CONTRACTS.md §6's "optional-by-design" a fact rather than
   an intention. Steps 13-19 each add a model; if any of them can take the
   pipeline down, the AI layer has stopped being an accelerator and become a
   dependency — and a dependency that decides whether someone's identity
   document can be checked.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from avs.ai.modelmgr import (
    MANIFEST_NAME,
    InferenceOutcome,
    ModelRegistry,
    ModelRunner,
    ModelSpec,
    RegistryError,
    load_registry,
)

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def write_model(directory: Path, name: str, content: bytes = b"fake-onnx-graph") -> str:
    """Write a stand-in model file and return its digest."""
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{name}.onnx").write_bytes(content)
    return hashlib.sha256(content).hexdigest()


def write_manifest(directory: Path, *entries: dict) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / MANIFEST_NAME).write_text(json.dumps({"models": list(entries)}), encoding="utf-8")


# --------------------------------------------------------------------------- #
# ⛔ No models at all is the NORMAL state
# --------------------------------------------------------------------------- #


def test_a_missing_model_directory_is_not_an_error(tmp_path: Path):
    """★ Running with no models is supported, not degraded.

    The deterministic pipeline is complete without any of them. Treating "no
    models" as a failure would invert the relationship — the accelerator would
    become the dependency.
    """
    registry = load_registry(tmp_path / "does-not-exist")

    assert registry.names == []
    assert registry.problems == {}


def test_a_missing_manifest_yields_an_empty_registry(tmp_path: Path):
    (tmp_path / "models").mkdir()
    assert load_registry(tmp_path / "models").names == []


def test_an_unknown_model_returns_none_rather_than_raising(tmp_path: Path):
    runner = ModelRunner(load_registry(tmp_path))
    assert runner.run("no-such-model", {}) is None


def test_with_fallback_takes_the_deterministic_path(tmp_path: Path):
    """The shape every ai/ module should use — the fallback cannot be forgotten."""
    runner = ModelRunner(load_registry(tmp_path))
    result = runner.with_fallback("absent", {}, lambda: "deterministic")

    assert result == "deterministic"


# --------------------------------------------------------------------------- #
# ⛔ Digest pinning — a model file is executable content
# --------------------------------------------------------------------------- #


def test_a_correctly_pinned_model_resolves(tmp_path: Path):
    digest = write_model(tmp_path, "quality")
    write_manifest(tmp_path, {"name": "quality", "version": "1.0.0", "sha256": digest})

    registry = load_registry(tmp_path)
    assert registry.path_for("quality") is not None
    assert registry.problems == {}


def test_a_swapped_model_file_is_refused(tmp_path: Path):
    """★ The attack this pinning exists for.

    An ONNX graph is a program interpreted by onnxruntime. Dropping a file into
    `models/` is closer to dropping a `.so` into the library path than to
    editing config, so the file must be the one we pinned.
    """
    digest = write_model(tmp_path, "quality", b"the-model-we-shipped")
    write_manifest(tmp_path, {"name": "quality", "version": "1.0.0", "sha256": digest})

    # Someone replaces it.
    (tmp_path / "quality.onnx").write_bytes(b"a-model-somebody-else-supplied")

    registry = load_registry(tmp_path)
    assert registry.path_for("quality") is None
    assert "digest mismatch" in registry.problems["quality"]


def test_a_missing_model_file_is_reported_not_raised(tmp_path: Path):
    write_manifest(tmp_path, {"name": "quality", "version": "1.0.0", "sha256": "a" * 64})

    registry = load_registry(tmp_path)
    assert registry.path_for("quality") is None
    assert "not found" in registry.problems["quality"]


@pytest.mark.parametrize("digest", ["", "abc", "z" * 64, "A" * 63])
def test_a_manifest_without_a_valid_digest_is_refused_at_load(tmp_path: Path, digest: str):
    """⛔ Refuse at load, not at first use.

    An unpinned model is unpinned whether or not anyone has run it. A manifest
    that parses but cannot be trusted is worse than one that fails outright.
    """
    write_manifest(tmp_path, {"name": "quality", "version": "1.0.0", "sha256": digest})

    with pytest.raises(RegistryError, match="sha256"):
        load_registry(tmp_path)


def test_a_duplicate_model_name_is_refused(tmp_path: Path):
    write_manifest(
        tmp_path,
        {"name": "quality", "version": "1", "sha256": "a" * 64},
        {"name": "quality", "version": "2", "sha256": "b" * 64},
    )
    with pytest.raises(RegistryError, match="duplicate"):
        load_registry(tmp_path)


def test_a_disabled_model_is_invisible(tmp_path: Path):
    digest = write_model(tmp_path, "quality")
    write_manifest(
        tmp_path,
        {"name": "quality", "version": "1.0.0", "sha256": digest, "enabled": False},
    )

    registry = load_registry(tmp_path)
    assert registry.get("quality") is None
    assert "quality" in registry.names  # declared, but not usable


# --------------------------------------------------------------------------- #
# ⛔ Degradation — every failure mode ends in "carry on"
# --------------------------------------------------------------------------- #


class ExplodingSession:
    """A model that throws. The most common real failure."""

    def run(self, _outputs, _inputs):
        raise RuntimeError("corrupt tensor")


class HangingSession:
    """A model that never returns. The most dangerous real failure."""

    def run(self, _outputs, _inputs):
        import time

        time.sleep(30)


class EmptySession:
    """A model that returns nothing useful."""

    def run(self, _outputs, _inputs):
        return []


def session_for(monkeypatch, tmp_path: Path, backend: object, *, budget_ms: int = 200):
    """A ModelRunner whose loader yields the given fake backend."""
    from avs.ai.modelmgr.runtime import InferenceSession

    spec = ModelSpec(
        name="quality",
        version="1.0.0",
        filename="quality.onnx",
        sha256="a" * 64,
        max_inference_ms=budget_ms,
    )
    runner = ModelRunner(ModelRegistry(tmp_path, {"quality": spec}))
    monkeypatch.setattr(runner, "_load", lambda _name: InferenceSession(spec, backend))
    return runner


def test_a_model_that_throws_degrades(monkeypatch, tmp_path: Path):
    runner = session_for(monkeypatch, tmp_path, ExplodingSession())
    outcome = runner.run("quality", {})

    assert outcome is not None
    assert outcome.usable is False
    assert "RuntimeError" in outcome.degraded_reason


def test_a_model_that_hangs_is_abandoned_within_its_budget(monkeypatch, tmp_path: Path):
    """★ The failure that would otherwise consume the whole document budget.

    The deterministic path was going to succeed anyway; a hung advisory model
    must not starve it.
    """
    import time

    runner = session_for(monkeypatch, tmp_path, HangingSession(), budget_ms=150)

    started = time.perf_counter()
    outcome = runner.run("quality", {})
    elapsed = time.perf_counter() - started

    assert outcome.usable is False
    assert "budget" in outcome.degraded_reason
    assert elapsed < 1.0, f"waited {elapsed:.1f}s for a model with a 150ms budget"


def test_a_model_that_returns_nothing_degrades(monkeypatch, tmp_path: Path):
    runner = session_for(monkeypatch, tmp_path, EmptySession())
    assert runner.run("quality", {}).usable is False


def test_a_working_model_produces_a_usable_outcome(monkeypatch, tmp_path: Path):
    """`onnxruntime.InferenceSession.run` returns a LIST OF OUTPUT ARRAYS — one
    entry per model output, not one per value. A single output holding two
    numbers therefore arrives as `([0.1, 0.9],)`, and flattening it here would
    silently merge the outputs of a two-headed model."""

    class GoodSession:
        def run(self, _outputs, _inputs):
            return [[0.1, 0.9]]  # one output, two values

    runner = session_for(monkeypatch, tmp_path, GoodSession())
    outcome = runner.run("quality", {})

    assert outcome.usable is True
    assert outcome.version == "1.0.0"
    assert outcome.outputs == ([0.1, 0.9],)
    assert len(outcome.outputs) == 1, "one model output, preserved as one entry"


def test_multiple_model_outputs_stay_separate(monkeypatch, tmp_path: Path):
    """A model with two heads — Step 14's quality model has several scores —
    must not have them flattened into one indistinguishable sequence."""

    class TwoHeadSession:
        def run(self, _outputs, _inputs):
            return [[0.8], [0.2, 0.1]]

    runner = session_for(monkeypatch, tmp_path, TwoHeadSession())
    outcome = runner.run("quality", {})

    assert outcome.outputs == ([0.8], [0.2, 0.1])


def test_fallback_is_used_when_a_model_degrades(monkeypatch, tmp_path: Path):
    runner = session_for(monkeypatch, tmp_path, ExplodingSession())
    result = runner.with_fallback("quality", {}, lambda: "deterministic")

    assert result == "deterministic"


# --------------------------------------------------------------------------- #
# ⛔ The AI boundary, expressed as a type constraint
# --------------------------------------------------------------------------- #


def test_the_inference_outcome_carries_no_verdict():
    """⛔ If a future step adds `is_genuine` or `verdict` here, that is the
    moment the AI boundary is being crossed — CONTRACTS.md §7.

    A model may say a photo looks blurry. It may never say a card is genuine.
    """
    forbidden = {"verdict", "verified", "is_genuine", "authentic", "signature_valid", "approved"}
    fields = set(InferenceOutcome.__dataclass_fields__)

    assert not (fields & forbidden), f"AI outcome exposes verdict fields: {fields & forbidden}"


def test_the_version_is_recorded_against_every_inference(monkeypatch, tmp_path: Path):
    """When a model misbehaves in production, "which version?" is the first
    question. An unversioned inference cannot answer it."""

    class GoodSession:
        def run(self, _outputs, _inputs):
            return [[1.0]]

    runner = session_for(monkeypatch, tmp_path, GoodSession())
    assert runner.run("quality", {}).version == "1.0.0"


def test_sessions_are_cached_including_failures(monkeypatch, tmp_path: Path):
    """A model that cannot load must not be retried on every document — that
    turns one missing file into a per-request filesystem stat."""
    calls: list[str] = []

    runner = ModelRunner(load_registry(tmp_path))

    def counting_load(name: str):
        calls.append(name)
        return None

    monkeypatch.setattr(runner, "_load", counting_load)

    for _ in range(5):
        runner.session_for("quality")

    assert len(calls) == 1


# --------------------------------------------------------------------------- #
# ⛔ Pinning must not manufacture false confidence
# --------------------------------------------------------------------------- #


def test_pinning_refuses_an_empty_file(tmp_path: Path):
    """★ Found by running `avs models pin` on a directory containing a 0-byte
    file: it pinned it, printing the SHA-256 of zero bytes.

    A digest over garbage is still a VALID digest. `models status` would then
    report "pinned ✓" and an operator would reasonably conclude the model had
    been verified. Pinning answers "is this the file we chose?" — it cannot
    answer "is this a model?", so that gap is closed at the CLI, the one point
    where a human is looking at the values before committing them.
    """
    from typer.testing import CliRunner

    from avs.cli import app

    (tmp_path / "quality.onnx").write_bytes(b"")

    result = CliRunner().invoke(app, ["models", "pin", "--dir", str(tmp_path)])

    assert result.exit_code == 1
    assert "EMPTY" in result.stdout
    assert "e3b0c44298fc1c14" not in result.stdout, "printed the empty-file digest"


def test_pinning_warns_about_an_implausibly_small_file(tmp_path: Path):
    """Not refused — it could be a legitimate tiny graph — but never silent."""
    from typer.testing import CliRunner

    from avs.cli import app

    (tmp_path / "quality.onnx").write_bytes(b"x" * 40)

    result = CliRunner().invoke(app, ["models", "pin", "--dir", str(tmp_path)])

    assert result.exit_code == 0
    assert "too small" in result.stdout
    assert "sha256" in result.stdout  # still pinned


def test_pinning_a_plausible_file_succeeds(tmp_path: Path):
    from typer.testing import CliRunner

    from avs.cli import app

    (tmp_path / "quality.onnx").write_bytes(b"x" * 50_000)

    result = CliRunner().invoke(app, ["models", "pin", "--dir", str(tmp_path)])

    assert result.exit_code == 0
    assert "EMPTY" not in result.stdout
    assert "too small" not in result.stdout
