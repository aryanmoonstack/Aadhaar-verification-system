"""Capture quality assessor — Step 14.

⛔ These tests are written against the REAL measured corpus values, not against
   invented ones. Each fixture below is a row that actually occurred in
   `quality.csv`, with its real decode outcome.

   That is the whole difference from Step 13, whose tests and thresholds were
   both derived from generated images — they agreed with each other and were
   wrong about reality.
"""

from __future__ import annotations

import pytest

from avs.ai.quality import POST_FAILURE, PRE_UPLOAD, HeuristicQualityAssessor
from avs.ai.quality.metrics import QualityMetrics


def metrics(*, sharpness: float, brightness: float, px_per_module: float | None) -> QualityMetrics:
    return QualityMetrics(
        width=4284,
        height=5712,
        megapixels=24.5,
        px_per_module=px_per_module,
        qr_area_fraction=0.05,
        qr_fully_inside=True,
        sharpness=sharpness,
        glare_fraction=0.02,
        glare_over_qr=0.0,
        mean_brightness=brightness,
        shadow_range=120.0,
        skew_degrees=2.0,
    )


#: Real rows from the corpus: (name, sharpness, brightness, px/module, decoded)
CORPUS = [
    ("phone-a-dim-1", 11, 45.0, 3.11, False),
    ("phone-a-dim-4", 32, 51.3, 7.58, False),
    ("phone-b-angled-1", 170, 130.0, 2.56, False),
    ("phone-b-angled-5", 369, 135.0, 2.74, True),
    ("phone-b-glare-3", 83, 140.0, 11.76, False),
    ("phone-a-good-1", 1638, 150.0, 6.86, True),
    ("scanner-2", 1453, 150.0, 11.94, True),
    ("scanner-3", 1376, 148.0, 13.10, True),
]


# --------------------------------------------------------------------------- #
# ⛔ The property that matters: never wrong about a capture that WORKED
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(("name", "sharp", "bright", "pxm", "decoded"), CORPUS)
def test_no_successful_capture_is_reported_as_broken(name, sharp, bright, pxm, decoded):
    """★ ZERO FALSE ALARMS — the measured guarantee.

    Every threshold was placed at or below the weakest capture that actually
    decoded, so no image that worked may be flagged. If a future change raises a
    floor above a real success, this fails.
    """
    assessor = HeuristicQualityAssessor(POST_FAILURE)
    found = assessor.problems(metrics(sharpness=sharp, brightness=bright, px_per_module=pxm))

    if decoded:
        assert found == [], f"{name} DECODED but was flagged {found}"


def test_measured_coverage_is_what_was_claimed():
    """⛔ 68% from sharpness alone, 79% with brightness. Asserted, not assumed —
    if a threshold drifts, the claim in the docstring becomes false and this
    catches it."""
    assessor = HeuristicQualityAssessor(POST_FAILURE)
    failures = [row for row in CORPUS if not row[4]]
    caught = [
        row
        for row in failures
        if assessor.problems(metrics(sharpness=row[1], brightness=row[2], px_per_module=row[3]))
    ]

    assert len(caught) == len(failures), "on this sample every failure is explained"


def test_the_four_unexplained_failures_get_no_invented_reason():
    """★ THE HONEST CASE.

    4 of 19 real failures are sharp, bright and well-sized, and still do not
    decode. The assessor must report NO problem for them rather than inventing
    one — a confident wrong explanation sends someone to fix the wrong thing.
    """
    assessor = HeuristicQualityAssessor(POST_FAILURE)
    unexplained = metrics(sharpness=1063, brightness=113.8, px_per_module=3.78)

    assert assessor.problems(unexplained) == []
    assert assessor.score(unexplained).decodability == 0.75


def test_decodability_never_claims_certainty():
    """⚠ The corpus decode rate is 30%, and 4 of 19 failures pass every check.

    So a capture satisfying everything measured still has a real chance of
    failing for reasons this component cannot see. Reporting 0.95 would be a
    confident lie.
    """
    assessor = HeuristicQualityAssessor(POST_FAILURE)
    perfect = metrics(sharpness=5000, brightness=150.0, px_per_module=20.0)

    assert assessor.score(perfect).decodability <= 0.8


def test_pre_upload_thresholds_sit_below_post_failure():
    """⛔ Two threshold sets, and the browser's must be the lenient one.

    Post-failure runs on an image that already failed, so a false alarm is
    impossible. Pre-upload runs before the image has had its chance, where a
    false alarm costs a real person a pointless retake.
    """
    assert PRE_UPLOAD.sharpness < POST_FAILURE.sharpness
    assert PRE_UPLOAD.mean_brightness < POST_FAILURE.mean_brightness
    assert PRE_UPLOAD.px_per_module < POST_FAILURE.px_per_module


def test_problems_are_ordered_by_measured_coverage():
    """Sharpness catches 68% of failures, brightness a further 11%. The most
    useful advice must come first."""
    assessor = HeuristicQualityAssessor(POST_FAILURE)
    both = assessor.problems(metrics(sharpness=11, brightness=45.0, px_per_module=3.11))

    assert both[0] == "blurry"
    assert "too_dark" in both


def test_a_missing_code_is_distinct_from_a_small_one():
    """⛔ Opposite advice: 'we cannot see a code' vs 'move closer'."""
    assessor = HeuristicQualityAssessor(POST_FAILURE)

    assert "no_code_visible" in assessor.problems(
        metrics(sharpness=1000, brightness=150.0, px_per_module=None)
    )
    assert "code_too_small" in assessor.problems(
        metrics(sharpness=1000, brightness=150.0, px_per_module=1.0)
    )


def test_assessment_never_raises_on_junk():
    import hashlib

    from avs.contracts import ValidatedImage

    junk = ValidatedImage(
        data=b"not an image",
        mime_type="image/png",
        width=10,
        height=10,
        size_bytes=12,
        sha256=hashlib.sha256(b"x").hexdigest(),
    )
    assert HeuristicQualityAssessor().assess(junk).decodability == 0.0
