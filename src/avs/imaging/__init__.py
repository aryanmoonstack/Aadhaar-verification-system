"""avs.imaging — deterministic image preprocessing.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 4
Provides : PreprocessingVariantGenerator, Strategy, Problem, STRATEGIES,
           select_strategies, ops, ImagingError
Consumes : avs.contracts, OpenCV, numpy
Used by  : avs.qr (Step 5)
Status   : COMPLETE

WHAT THIS MODULE IS FOR
-----------------------
With PDF out of scope, every input is a camera or scanner capture. Turning a
real-world phone photo into something a dense QR decoder can read is now the
entire game — decode rate is the project's primary metric, and this is the
module that moves it.

LAZY, CHEAPEST-FIRST
--------------------
Variants are yielded one at a time in tier order. The Step 5 cascade stops at the
first success, so a good capture costs one or two variants and only a genuinely
difficult one pays for the full matrix. Contract 1.1.0 widened
``VariantGenerator.generate`` to ``Iterable`` to permit this.

SEAMS ALREADY WIRED
-------------------
* ``quality`` (Step 14) — narrows the strategy set to the problems actually
  detected, instead of running all of them.
* ``region`` (Step 15) — crops to the located QR before processing.

Both default to ``None``, in which case the full deterministic matrix runs.
"""

from avs.imaging import ops
from avs.imaging.errors import ImagingError
from avs.imaging.generator import PreprocessingVariantGenerator
from avs.imaging.strategy import (
    STRATEGIES,
    Problem,
    Strategy,
    problems_from_quality,
    select_strategies,
)

__all__ = [
    "STRATEGIES",
    "ImagingError",
    "PreprocessingVariantGenerator",
    "Problem",
    "Strategy",
    "ops",
    "problems_from_quality",
    "select_strategies",
]
