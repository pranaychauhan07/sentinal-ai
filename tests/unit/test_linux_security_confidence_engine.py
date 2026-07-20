"""Unit tests for core/linux_security/confidence_engine.py."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from core.linux_security.confidence_engine import (
    LinuxSecurityConfidenceEngine,
    LinuxSecurityConfidenceWeights,
)
from core.linux_security.models import (
    LinuxSecurityCandidate,
    LinuxSecurityFindingCategory,
    LinuxSecuritySeverity,
)

pytestmark = pytest.mark.unit


def _candidate(**overrides: object) -> LinuxSecurityCandidate:
    now = datetime.now(UTC)
    defaults: dict[str, object] = {
        "category": LinuxSecurityFindingCategory.BRUTE_FORCE,
        "severity": LinuxSecuritySeverity.HIGH,
        "subject": "1.2.3.4",
        "title": "t",
        "first_seen": now,
        "last_seen": now,
    }
    defaults.update(overrides)
    return LinuxSecurityCandidate(**defaults)  # type: ignore[arg-type]


def test_weights_must_sum_to_one() -> None:
    with pytest.raises(ValueError, match="sum to 1.0"):
        LinuxSecurityConfidenceWeights(
            pattern_match_strength=0.5,
            occurrence_signal=0.5,
            evidence_completeness=0.5,
            corroboration=0.5,
        )


def test_default_weights_are_valid() -> None:
    LinuxSecurityConfidenceWeights()  # must not raise


def test_higher_occurrence_count_increases_confidence() -> None:
    engine = LinuxSecurityConfidenceEngine()
    low = engine.calculate(_candidate(occurrence_count=1))
    high = engine.calculate(_candidate(occurrence_count=10))
    assert high > low


def test_corroboration_increases_confidence() -> None:
    engine = LinuxSecurityConfidenceEngine()
    candidate = _candidate()
    uncorroborated = engine.calculate(candidate, corroborating_count=0)
    corroborated = engine.calculate(candidate, corroborating_count=2)
    assert corroborated > uncorroborated


def test_confidence_bounded_between_zero_and_one() -> None:
    engine = LinuxSecurityConfidenceEngine()
    value = engine.calculate(_candidate(occurrence_count=1000), corroborating_count=100)
    assert 0.0 <= value <= 1.0


def test_deterministic_given_same_input() -> None:
    engine = LinuxSecurityConfidenceEngine()
    candidate = _candidate()
    assert engine.calculate(candidate) == engine.calculate(candidate)
