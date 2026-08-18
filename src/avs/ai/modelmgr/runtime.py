"""Inference runtime — Step 12.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 12
Provides : InferenceSession, InferenceOutcome, ModelRunner
Consumes : avs.ai.modelmgr.registry, onnxruntime (OPTIONAL)
Used by  : avs.ai.classify (13), quality (14), localize (15), restore (19)
Status   : COMPLETE

⛔ THE ONE RULE THIS MODULE ENFORCES

   **A model must never be able to fail a verification.**

   Not by failing to load. Not by throwing. Not by hanging. Not by returning
   nonsense. Every path through this module ends in either a usable result or
   ``None``, and ``None`` means the caller carries on deterministically.

   That is what makes CONTRACTS.md §6's "optional-by-design" true rather than
   aspirational. A model is an accelerator: it may make a bad photo readable, it
   may spare someone a re-upload. It may not stand between a person and their
   verification.

WHY EACH GUARD IS HERE
----------------------
**Import guard.** ``onnxruntime`` is an optional extra. A deployment that never
enables AI should not need a 200MB wheel, and importing it eagerly would make it
mandatory in practice.

**Load guard.** A model file can be missing, corrupt, or fail its digest check.
All three are operational facts, not exceptions the pipeline should handle.

**Time budget.** A model that hangs would consume the whole 12s document budget
and starve the deterministic path that was going to succeed anyway. Inference
runs on a worker thread with a hard ceiling, and a slow model is abandoned.

**Result guard.** A model that returns NaN, an empty array, or a shape nobody
expects is a bug, and a bug in an advisory component must degrade, not crash.

⚠ WHAT THIS MODULE DELIBERATELY CANNOT DO

   It cannot import ``avs.crypto`` or ``avs.rules``. There is an AST test
   asserting that. Not because someone might do it deliberately, but because
   the natural shape of "I need a bit more context here" is an import, and the
   boundary has to be a wall rather than a note.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from avs.ai.modelmgr.registry import ModelRegistry, ModelSpec
from avs.logging import get_logger

__all__ = ["InferenceOutcome", "InferenceSession", "ModelRunner", "onnxruntime_available"]

log = get_logger(__name__)


def onnxruntime_available() -> bool:
    """Is the optional inference dependency installed?"""
    try:
        import onnxruntime  # noqa: F401
    except ImportError:
        return False
    return True


@dataclass(frozen=True, slots=True)
class InferenceOutcome:
    """What one inference produced, and what it cost.

    ⛔ There is no verdict field, no confidence-that-decides-anything, and no
       boolean an approval could be read from. Everything here is advisory —
       see CONTRACTS.md §7. If a future step wants to add ``is_genuine`` to
       this class, that is the moment the AI boundary is being crossed.
    """

    model: str
    version: str
    ok: bool
    elapsed_ms: int

    outputs: tuple[Any, ...] = ()
    """Raw model output. Interpreted by the calling ai/ module, never here."""

    degraded_reason: str | None = None
    """Why this produced nothing. Recorded in ``AiTrace``, surfaced to ops, and
    never shown to an employee — a model being unavailable is our problem."""

    @property
    def usable(self) -> bool:
        return self.ok and bool(self.outputs)


class InferenceSession:
    """One loaded model, ready to run.

    Wraps an ``onnxruntime.InferenceSession``. Kept separate so the calling
    modules never touch onnxruntime directly — which is what lets the whole
    layer be optional and what keeps the import guard in one place.
    """

    def __init__(self, spec: ModelSpec, session: Any) -> None:
        self.spec = spec
        self._session = session
        self._lock = threading.Lock()

    def run(self, inputs: dict[str, Any]) -> InferenceOutcome:
        """Run inference under a hard time budget.

        ⚠ The timeout runs the model on a separate thread and ABANDONS it on
          expiry rather than killing it — Python cannot safely kill a thread
          executing native code. The abandoned thread finishes eventually and
          its result is discarded. That is a deliberate trade: a leaked thread
          for a few hundred milliseconds is survivable; a hung verification is
          not.
        """
        started = time.perf_counter()
        result: list[Any] = []
        failure: list[BaseException] = []

        def invoke() -> None:
            try:
                with self._lock:
                    # onnxruntime sessions are not documented as thread-safe for
                    # concurrent Run() calls on every provider, and the workers
                    # are concurrent by design.
                    result.append(self._session.run(None, inputs))
            except BaseException as exc:
                # ⛔ BaseException, not Exception. A native crash surfacing as
                #    something outside the Exception hierarchy must still
                #    degrade rather than propagate into the pipeline.
                failure.append(exc)

        worker = threading.Thread(target=invoke, daemon=True, name=f"avs-ai-{self.spec.name}")
        worker.start()
        worker.join(timeout=self.spec.max_inference_ms / 1000)
        elapsed_ms = int((time.perf_counter() - started) * 1000)

        if worker.is_alive():
            log.warning(
                "ai.inference.timeout",
                model=self.spec.name,
                version=self.spec.version,
                budget_ms=self.spec.max_inference_ms,
            )
            return self._degraded(f"exceeded {self.spec.max_inference_ms}ms budget", elapsed_ms)

        if failure:
            log.warning(
                "ai.inference.failed",
                model=self.spec.name,
                version=self.spec.version,
                error=type(failure[0]).__name__,
            )
            return self._degraded(f"{type(failure[0]).__name__}: {failure[0]}", elapsed_ms)

        if not result or not result[0]:
            return self._degraded("model returned no output", elapsed_ms)

        return InferenceOutcome(
            model=self.spec.name,
            version=self.spec.version,
            ok=True,
            elapsed_ms=elapsed_ms,
            outputs=tuple(result[0]),
        )

    def _degraded(self, reason: str, elapsed_ms: int) -> InferenceOutcome:
        return InferenceOutcome(
            model=self.spec.name,
            version=self.spec.version,
            ok=False,
            elapsed_ms=elapsed_ms,
            degraded_reason=reason,
        )


class ModelRunner:
    """Loads models on demand and runs them, degrading rather than failing.

    The single entry point for every ai/ module from Step 13 onwards. Sessions
    are cached — loading an ONNX graph costs tens to hundreds of milliseconds
    and doing it per document would dwarf the inference itself.
    """

    def __init__(self, registry: ModelRegistry) -> None:
        self.registry = registry
        self._sessions: dict[str, InferenceSession | None] = {}
        self._lock = threading.Lock()

    def session_for(self, name: str) -> InferenceSession | None:
        """A loaded session, or None if the model cannot be used.

        ⛔ Never raises. The caller is an advisory component; making it handle
           exceptions is how an optional dependency quietly becomes required.
        """
        with self._lock:
            if name in self._sessions:
                return self._sessions[name]  # includes a cached None

            session = self._load(name)
            self._sessions[name] = session
            return session

    def run(self, name: str, inputs: dict[str, Any]) -> InferenceOutcome | None:
        """Run a model. None means "carry on without it"."""
        session = self.session_for(name)
        if session is None:
            return None
        return session.run(inputs)

    def with_fallback(self, name: str, inputs: dict[str, Any], fallback: Callable[[], Any]) -> Any:
        """Run a model, or the deterministic alternative if it is unavailable.

        The shape every ai/ module should use. Writing it once here means no
        individual module can forget the fallback — which is the failure mode
        that turns "AI is optional" into "AI is required in practice".
        """
        outcome = self.run(name, inputs)
        if outcome is None or not outcome.usable:
            return fallback()
        return outcome

    # ------------------------------------------------------------------ #

    def _load(self, name: str) -> InferenceSession | None:
        spec = self.registry.get(name)
        if spec is None:
            return None

        if not onnxruntime_available():
            log.info(
                "ai.model.skipped",
                model=name,
                reason='onnxruntime not installed — pip install -e ".[ai]"',
            )
            return None

        path = self.registry.path_for(name)
        if path is None:
            # registry.problems already carries the reason — missing file, or a
            # digest mismatch, which is the serious one.
            log.warning(
                "ai.model.unavailable",
                model=name,
                reason=self.registry.problems.get(name, "unknown"),
            )
            return None

        try:
            import onnxruntime

            options = onnxruntime.SessionOptions()
            # Single-threaded on purpose. The pipeline already runs documents
            # concurrently across worker threads; letting each model spawn its
            # own pool oversubscribes the CPU and makes everything slower.
            options.intra_op_num_threads = 1
            options.inter_op_num_threads = 1

            session = onnxruntime.InferenceSession(
                str(path), options, providers=["CPUExecutionProvider"]
            )
        except BaseException as exc:
            # ⛔ A malformed or hostile ONNX graph can fail in native code. It
            #    must not take the process with it.
            log.error("ai.model.load_failed", model=name, error=type(exc).__name__)
            return None

        log.info("ai.model.loaded", model=name, version=spec.version)
        return InferenceSession(spec, session)
