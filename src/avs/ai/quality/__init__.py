"""avs.ai.quality — Capture quality assessment (Step 14).

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 14
Provides : QualityMetrics, measure_quality(), MODULES_ACROSS,
           HeuristicQualityAssessor, POST_FAILURE, PRE_UPLOAD
Consumes : avs.imaging.ops
Used by  : avs.pipeline (optional), scripts/measure_decode_quality.py
Status   : COMPLETE — thresholds derived from 27 real decode outcomes

⛔ THRESHOLDS ARE NOT SET IN THIS PACKAGE YET, ON PURPOSE.

   Step 13's classifier was tuned on generated images, agreed with itself
   perfectly, and caught 0 of 19 real wrong-uploads. The failure was not bad
   luck — it was deriving a threshold from data that shared the code's own
   assumptions.

   So `measure_quality()` shipped first, alone, and
   `scripts/measure_decode_quality.py` paired its output with REAL decode
   outcomes on a real corpus. `assessor.py` was written only afterwards, with
   numbers taken from that table:

       sharpness floor 368.76 -> flags 68% of failures, 0 false alarms
       brightness floor 108.73 -> a further 11%
       combined                -> 79%

   ⛔ That process caught a genuine bug in shipping code on the way through:
      `find_qr_region` was returning non-square regions spanning whole cards
      (aspect ratios down to 0.51), inflating every px_per_module measurement
      roughly 3x. See D137.
"""

from avs.ai.quality.assessor import (
    POST_FAILURE,
    PRE_UPLOAD,
    HeuristicQualityAssessor,
    QualityThresholds,
)
from avs.ai.quality.metrics import MODULES_ACROSS, QualityMetrics, measure_quality

__all__ = [
    "MODULES_ACROSS",
    "POST_FAILURE",
    "PRE_UPLOAD",
    "HeuristicQualityAssessor",
    "QualityMetrics",
    "QualityThresholds",
    "measure_quality",
]
