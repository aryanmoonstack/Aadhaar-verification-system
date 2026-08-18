"""Model registry — Step 12.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 12
Provides : ModelSpec, ModelRegistry, RegistryError, load_registry()
Consumes : avs.contracts
Used by  : avs.ai.modelmgr.runtime, and through it every ai/ module (Steps 13-19)
Status   : COMPLETE

WHAT THIS EXISTS TO DO
----------------------
Steps 13 to 19 each add a model. Without a registry each would invent its own
loading, its own versioning and its own failure behaviour, and the pipeline
would have five subtly different ways to break. This is the one place that
answers: which file, which version, is it the file we expect, and what happens
when it is not.

⛔ A MODEL FILE IS EXECUTABLE CONTENT, NOT DATA

   An ONNX graph is a program. It is interpreted by onnxruntime, it can contain
   custom operators, and a maliciously crafted one is an attack on the process
   that loads it. Dropping a file into ``models/`` is therefore closer to
   dropping a ``.so`` into the library path than to adding a config file.

   So models are pinned by SHA-256, exactly as UIDAI certificates are pinned in
   ``avs.truststore``. A file whose digest is not listed is refused, loudly,
   before onnxruntime ever sees it. The reasoning is identical: a trusted file
   in a trusted directory is a capability, and capabilities need provenance.

⚠ THIS IS NOT THE VERDICT PATH

   Nothing here can produce a Verdict — CONTRACTS.md §7. If every model in this
   registry were replaced with a hostile one, the worst outcome is bad
   preprocessing advice and a re-upload prompt. Forging an approval still
   requires UIDAI's private key. The pinning below is defence in depth, not the
   thing standing between an attacker and an approval.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "MANIFEST_NAME",
    "ModelRegistry",
    "ModelSpec",
    "RegistryError",
    "load_registry",
]

#: Declares which models exist, their versions and their expected digests.
MANIFEST_NAME = "models.json"

#: Read in chunks — a model can be hundreds of megabytes and reading it whole
#: to hash it would spike memory on a container with a modest limit.
_HASH_CHUNK_BYTES = 1024 * 1024


class RegistryError(Exception):
    """The registry could not be loaded, or a model failed verification."""

    def __init__(self, message: str, *, model: str | None = None) -> None:
        self.message = message
        self.model = model
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class ModelSpec:
    """One model: where it lives, which version, and what it should hash to."""

    name: str
    """Stable identifier, e.g. ``capture_quality``. Used in ``AiTrace.models_used``."""

    version: str
    """⚠ Recorded against every inference. When a model starts behaving oddly in
    production, "which version produced this?" is the first question, and an
    unversioned model makes it unanswerable."""

    filename: str
    sha256: str
    """Expected digest. The registry refuses to load anything that differs."""

    purpose: str = ""
    enabled: bool = True

    input_name: str = "input"
    output_names: tuple[str, ...] = ()

    max_inference_ms: int = 500
    """⛔ Hard ceiling. See ``runtime`` — a model that hangs must never hang a
    verification. 500ms is generous for the small vision models this project
    uses and still far below the 12s document budget."""

    def digest_of(self, path: Path) -> str:
        """SHA-256 of the file on disk."""
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(_HASH_CHUNK_BYTES):
                digest.update(chunk)
        return digest.hexdigest()


class ModelRegistry:
    """Models declared in a manifest, verified against their pinned digests.

    Loading is **lazy and non-fatal**: a missing or corrupt model removes that
    one capability and leaves everything else working. That is the whole point
    of the AI layer being optional — see CONTRACTS.md §6.
    """

    def __init__(self, model_dir: Path, specs: dict[str, ModelSpec]) -> None:
        self.model_dir = model_dir
        self._specs = specs
        self._problems: dict[str, str] = {}

    # ------------------------------------------------------------------ #

    @property
    def names(self) -> list[str]:
        """Every declared model, enabled or not."""
        return sorted(self._specs)

    @property
    def problems(self) -> dict[str, str]:
        """Models that could not be used, and why. For ``/ready`` and the CLI."""
        return dict(self._problems)

    def get(self, name: str) -> ModelSpec | None:
        """The spec, or None if unknown or disabled."""
        spec = self._specs.get(name)
        return spec if spec and spec.enabled else None

    def path_for(self, name: str) -> Path | None:
        """Verified path to the model file, or None if it cannot be trusted.

        ⛔ Returns None rather than raising. A caller that must decide whether to
           run a model should not have to wrap it in try/except — forgetting to
           is how an optional dependency becomes a hard one.
        """
        spec = self.get(name)
        if spec is None:
            return None

        path = self.model_dir / spec.filename
        if not path.is_file():
            self._note(name, f"file not found: {path}")
            return None

        actual = spec.digest_of(path)
        if actual != spec.sha256:
            # ⛔ Loud, and never loaded. This is either corruption or someone
            #    swapping a model file, and we cannot tell which from here.
            self._note(
                name,
                f"digest mismatch — expected {spec.sha256[:16]}…, "
                f"found {actual[:16]}…. Refusing to load.",
            )
            return None

        return path

    def _note(self, name: str, reason: str) -> None:
        self._problems[name] = reason


def load_registry(model_dir: str | Path) -> ModelRegistry:
    """Read ``models.json`` from a directory.

    An absent directory or manifest yields an EMPTY registry rather than an
    error. Running with no models at all is the normal, supported state — every
    AI capability is optional and the deterministic pipeline is complete without
    them. Treating "no models" as a failure would make the accelerator a
    dependency, which is precisely backwards.
    """
    directory = Path(model_dir)
    manifest = directory / MANIFEST_NAME

    if not manifest.is_file():
        return ModelRegistry(directory, {})

    try:
        document = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RegistryError(f"could not read {manifest}: {exc}") from exc

    entries = document.get("models")
    if not isinstance(entries, list):
        raise RegistryError(f"{manifest} has no 'models' list")

    specs: dict[str, ModelSpec] = {}
    for entry in entries:
        spec = _build_spec(entry, manifest)
        if spec.name in specs:
            raise RegistryError(f"duplicate model name {spec.name!r}", model=spec.name)
        specs[spec.name] = spec

    return ModelRegistry(directory, specs)


def _build_spec(entry: dict, manifest: Path) -> ModelSpec:
    name = str(entry.get("name", "")).strip()
    if not name:
        raise RegistryError(f"a model entry in {manifest} has no name")

    digest = str(entry.get("sha256", "")).strip().lower()
    if len(digest) != 64 or not all(c in "0123456789abcdef" for c in digest):
        # ⛔ Refuse at load, not at first use. An unpinned model is an unpinned
        #    model whether or not anyone has run it yet, and a manifest that
        #    parses but cannot be trusted is worse than one that fails outright.
        raise RegistryError(
            f"model {name!r} has no valid sha256. Compute it with:\n"
            f'    python -c "import hashlib,sys;'
            f"print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())\" <file>",
            model=name,
        )

    return ModelSpec(
        name=name,
        version=str(entry.get("version", "unversioned")),
        filename=str(entry.get("filename", f"{name}.onnx")),
        sha256=digest,
        purpose=str(entry.get("purpose", "")),
        enabled=bool(entry.get("enabled", True)),
        input_name=str(entry.get("input_name", "input")),
        output_names=tuple(entry.get("output_names", ())),
        max_inference_ms=int(entry.get("max_inference_ms", 500)),
    )
