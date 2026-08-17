"""Preprocessing strategies — Step 4. ★ The seam for Step 14.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 4
Provides : Strategy, Problem, STRATEGIES, select_strategies()
Consumes : avs.contracts, avs.imaging.ops
Used by  : avs.imaging.generator, avs.ai.quality (Step 14)

WHY STRATEGIES ARE DATA, NOT CODE
---------------------------------
Each strategy is a named recipe: an ordered list of operations, a cost tier, and
— crucially — the set of *problems it addresses*.

That last field is what makes Step 14 a configuration change rather than a
rewrite. Today, with no quality model, we run every strategy in tier order.
Tomorrow, when ``ai/quality/`` reports "this image is blurry but evenly lit", we
select only the strategies that address blur and skip the eight that fix
illumination. Same recipes, smaller set.

Expressing that as a table also means a human can read the whole preprocessing
policy in one screen and reason about it — which matters when decode rate is the
project's primary metric and this is the module that moves it.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from enum import Enum

import numpy as np

from avs.contracts import QualityScores
from avs.imaging import ops

__all__ = ["STRATEGIES", "Problem", "Strategy", "problems_from_quality", "select_strategies"]

Operation = Callable[[np.ndarray], np.ndarray]


class Problem(str, Enum):
    """What stops a dense QR from decoding in a real photograph."""

    NONE = "none"
    """The image may already be fine — always tried first."""

    CONTRAST = "contrast"
    """Grey-on-grey capture; modules barely separate from the background."""

    ILLUMINATION = "illumination"
    """Uneven lighting or a bright patch across the card."""

    GLARE = "glare"
    """Specular reflection saturating part of the code."""

    RESOLUTION = "resolution"
    """Too few pixels per QR module."""

    BLUR = "blur"
    """Defocus or motion smearing module edges together."""

    NOISE = "noise"
    """Sensor noise, typical of low-light phone captures."""

    PERSPECTIVE = "perspective"
    """Card photographed at an angle; the QR is a trapezoid."""


@dataclass(frozen=True, slots=True)
class Strategy:
    """One named preprocessing recipe."""

    name: str
    operations: tuple[Operation, ...]
    tier: int
    addresses: frozenset[Problem] = field(default_factory=frozenset)
    needs_warp: bool = False
    """Run against the perspective-corrected image rather than the original."""

    def apply(self, image: np.ndarray) -> np.ndarray:
        result = image
        for operation in self.operations:
            result = operation(result)
        return result


# --------------------------------------------------------------------------- #
# The strategy table
#
# Ordered by tier, cheapest first. The Step 5 cascade stops at the first
# successful decode, so ordering directly determines average latency.
# --------------------------------------------------------------------------- #

STRATEGIES: tuple[Strategy, ...] = (
    # ── Tier 0: near-free. A good capture decodes here and we stop. ──────────
    Strategy(
        name="original",
        operations=(),
        tier=0,
        addresses=frozenset({Problem.NONE}),
    ),
    Strategy(
        name="gray",
        operations=(ops.to_grayscale,),
        tier=0,
        addresses=frozenset({Problem.NONE}),
    ),
    Strategy(
        name="gray+clahe",
        operations=(ops.to_grayscale, ops.clahe),
        tier=0,
        addresses=frozenset({Problem.CONTRAST, Problem.ILLUMINATION}),
    ),
    # ── Tier 1: single targeted correction. ──────────────────────────────────
    Strategy(
        name="gray+otsu",
        operations=(ops.to_grayscale, ops.otsu_threshold),
        tier=1,
        addresses=frozenset({Problem.CONTRAST}),
    ),
    Strategy(
        name="gray+adaptive",
        operations=(ops.to_grayscale, ops.adaptive_threshold),
        tier=1,
        addresses=frozenset({Problem.ILLUMINATION, Problem.CONTRAST}),
    ),
    Strategy(
        name="gray+flatfield",
        operations=(ops.to_grayscale, ops.normalise_illumination),
        tier=1,
        addresses=frozenset({Problem.ILLUMINATION}),
    ),
    Strategy(
        name="gray+sharpen",
        operations=(ops.to_grayscale, ops.unsharp_mask),
        tier=1,
        addresses=frozenset({Problem.BLUR}),
    ),
    Strategy(
        name="gray+upscale",
        operations=(ops.to_grayscale, ops.upscale),
        tier=1,
        addresses=frozenset({Problem.RESOLUTION}),
    ),
    Strategy(
        name="gray+deglare",
        operations=(ops.to_grayscale, ops.suppress_glare),
        tier=1,
        addresses=frozenset({Problem.GLARE}),
    ),
    # ── Tier 2: combinations. Most real recoveries happen here. ──────────────
    Strategy(
        name="gray+clahe+sharpen",
        operations=(ops.to_grayscale, ops.clahe, ops.unsharp_mask),
        tier=2,
        addresses=frozenset({Problem.CONTRAST, Problem.BLUR}),
    ),
    Strategy(
        name="gray+flatfield+adaptive",
        operations=(ops.to_grayscale, ops.normalise_illumination, ops.adaptive_threshold),
        tier=2,
        addresses=frozenset({Problem.ILLUMINATION, Problem.CONTRAST}),
    ),
    Strategy(
        name="gray+flatfield+otsu",
        operations=(ops.to_grayscale, ops.normalise_illumination, ops.otsu_threshold),
        tier=2,
        addresses=frozenset({Problem.ILLUMINATION}),
    ),
    Strategy(
        name="gray+clahe+adaptive",
        operations=(ops.to_grayscale, ops.clahe, ops.adaptive_threshold),
        tier=2,
        addresses=frozenset({Problem.CONTRAST, Problem.ILLUMINATION}),
    ),
    Strategy(
        name="gray+upscale+sharpen",
        operations=(ops.to_grayscale, ops.upscale, ops.unsharp_mask),
        tier=2,
        addresses=frozenset({Problem.RESOLUTION, Problem.BLUR}),
    ),
    Strategy(
        name="gray+denoise+clahe",
        operations=(ops.to_grayscale, ops.denoise, ops.clahe),
        tier=2,
        addresses=frozenset({Problem.NOISE, Problem.CONTRAST}),
    ),
    Strategy(
        name="gray+deglare+adaptive",
        operations=(ops.to_grayscale, ops.suppress_glare, ops.adaptive_threshold),
        tier=2,
        addresses=frozenset({Problem.GLARE, Problem.ILLUMINATION}),
    ),
    # ── Tier 3: perspective correction, then the tier-0/1 recipes again. ─────
    #
    # Warping is expensive and can go wrong, so it runs late — but when the card
    # really was photographed at an angle, nothing else will recover it.
    Strategy(
        name="warp+gray",
        operations=(ops.to_grayscale,),
        tier=3,
        addresses=frozenset({Problem.PERSPECTIVE}),
        needs_warp=True,
    ),
    Strategy(
        name="warp+gray+clahe",
        operations=(ops.to_grayscale, ops.clahe),
        tier=3,
        addresses=frozenset({Problem.PERSPECTIVE, Problem.CONTRAST}),
        needs_warp=True,
    ),
    Strategy(
        name="warp+gray+adaptive",
        operations=(ops.to_grayscale, ops.adaptive_threshold),
        tier=3,
        addresses=frozenset({Problem.PERSPECTIVE, Problem.ILLUMINATION}),
        needs_warp=True,
    ),
    Strategy(
        name="warp+gray+upscale+sharpen",
        operations=(ops.to_grayscale, ops.upscale, ops.unsharp_mask),
        tier=3,
        addresses=frozenset({Problem.PERSPECTIVE, Problem.RESOLUTION, Problem.BLUR}),
        needs_warp=True,
    ),
    # ── Tier 4: last resort. Aggressive combinations. ────────────────────────
    Strategy(
        name="gray+denoise+flatfield+adaptive",
        operations=(
            ops.to_grayscale,
            ops.denoise,
            ops.normalise_illumination,
            ops.adaptive_threshold,
        ),
        tier=4,
        addresses=frozenset({Problem.NOISE, Problem.ILLUMINATION}),
    ),
    Strategy(
        name="gray+upscale+clahe+sharpen+adaptive",
        operations=(
            ops.to_grayscale,
            ops.upscale,
            ops.clahe,
            ops.unsharp_mask,
            ops.adaptive_threshold,
        ),
        tier=4,
        addresses=frozenset({Problem.RESOLUTION, Problem.BLUR, Problem.CONTRAST}),
    ),
    Strategy(
        name="gray+deglare+flatfield+clahe",
        operations=(
            ops.to_grayscale,
            ops.suppress_glare,
            ops.normalise_illumination,
            ops.clahe,
        ),
        tier=4,
        addresses=frozenset({Problem.GLARE, Problem.ILLUMINATION, Problem.CONTRAST}),
    ),
)


# --------------------------------------------------------------------------- #
# ★ Selection — where Step 14 plugs in
# --------------------------------------------------------------------------- #


def problems_from_quality(quality: QualityScores) -> set[Problem]:
    """Translate the Step 14 model's scores into the problems it detected.

    This is the whole integration surface for the quality model: a handful of
    thresholds mapping continuous scores onto the vocabulary the strategy table
    already speaks.
    """
    problems: set[Problem] = {Problem.NONE}

    if quality.blur < 0.6:
        problems.add(Problem.BLUR)
    if quality.glare < 0.7:
        problems.add(Problem.GLARE)
        problems.add(Problem.ILLUMINATION)
    if quality.shadow < 0.7:
        problems.add(Problem.ILLUMINATION)
    if not quality.resolution_adequate:
        problems.add(Problem.RESOLUTION)
    if abs(quality.skew_degrees) > 5.0:
        problems.add(Problem.PERSPECTIVE)
    if quality.decodability < 0.5:
        # The model expects trouble but cannot say precisely what. Fall back to
        # the full matrix rather than guessing wrong and skipping the one
        # strategy that would have worked.
        problems.update(Problem)

    return problems


def select_strategies(
    quality: QualityScores | None = None,
    *,
    max_tier: int = 4,
    limit: int | None = None,
) -> Sequence[Strategy]:
    """Choose which strategies to run, cheapest tier first.

    Args:
        quality: Step 14 output. ``None`` — the situation until Step 14 lands —
            selects the full deterministic matrix.
        max_tier: skip strategies above this cost tier.
        limit: hard cap on how many strategies to return.

    With no quality model this returns every strategy up to ``max_tier``, in tier
    order. With one, it returns tier-0 strategies (always — a good capture should
    still short-circuit immediately) plus those addressing the detected problems.
    """
    candidates = [s for s in STRATEGIES if s.tier <= max_tier]

    if quality is not None:
        problems = problems_from_quality(quality)
        candidates = [s for s in candidates if s.tier == 0 or (s.addresses & problems)]

    # Sort by tier, then by position in STRATEGIES — NOT alphabetically.
    # Within a tier the declaration order encodes intent: "original" must be
    # tried before "gray+clahe", because an already-good capture should decode
    # on the very first variant and stop. Sorting by name would put "gray"
    # first and quietly add work to every successful upload.
    order = {strategy.name: index for index, strategy in enumerate(STRATEGIES)}
    candidates.sort(key=lambda s: (s.tier, order[s.name]))
    return candidates[:limit] if limit else candidates
