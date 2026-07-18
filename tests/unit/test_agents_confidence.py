from __future__ import annotations

import pytest

from core.agents.confidence import (
    DETERMINISTIC_CONFIDENCE,
    LLM_FALLBACK_CONFIDENCE_CEILING,
    ConfidenceLevel,
    ConfidenceScore,
    classify_confidence,
)

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (1.0, ConfidenceLevel.CERTAIN),
        (0.95, ConfidenceLevel.CERTAIN),
        (0.94, ConfidenceLevel.HIGH),
        (0.7, ConfidenceLevel.HIGH),
        (0.69, ConfidenceLevel.MEDIUM),
        (0.4, ConfidenceLevel.MEDIUM),
        (0.39, ConfidenceLevel.LOW),
        (0.15, ConfidenceLevel.LOW),
        (0.14, ConfidenceLevel.UNKNOWN),
        (0.0, ConfidenceLevel.UNKNOWN),
    ],
)
def test_classify_confidence_buckets(value: float, expected: ConfidenceLevel) -> None:
    assert classify_confidence(value) is expected


def test_deterministic_confidence_is_always_maximal() -> None:
    score = ConfidenceScore.deterministic("parsed exactly")
    assert score.value == DETERMINISTIC_CONFIDENCE
    assert score.level is ConfidenceLevel.CERTAIN


def test_llm_fallback_confidence_is_capped() -> None:
    score = ConfidenceScore.llm_fallback(0.99, rationale="model guessed")
    assert score.value == LLM_FALLBACK_CONFIDENCE_CEILING
    assert score.level is ConfidenceLevel.HIGH


def test_llm_fallback_confidence_below_ceiling_is_unchanged() -> None:
    score = ConfidenceScore.llm_fallback(0.2)
    assert score.value == 0.2
    assert score.level is ConfidenceLevel.LOW


def test_confidence_score_is_frozen() -> None:
    score = ConfidenceScore.deterministic()
    with pytest.raises(Exception):  # noqa: B017, PT011 - pydantic's own frozen-instance error
        score.value = 0.1  # type: ignore[misc]


def test_confidence_score_rejects_out_of_range_value() -> None:
    with pytest.raises(Exception):  # noqa: B017, PT011 - pydantic ValidationError
        ConfidenceScore(value=1.5, level=ConfidenceLevel.CERTAIN)
