"""Unit tests for core/linux_security/scoring.py."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from core.linux_security.confidence_engine import LinuxSecurityConfidenceEngine
from core.linux_security.models import (
    LinuxSecurityCandidate,
    LinuxSecurityFindingCategory,
    LinuxSecuritySeverity,
)
from core.linux_security.scoring import (
    LinuxSecurityScoringWeights,
    LinuxThreatScoringEngine,
    score_candidates,
)

pytestmark = pytest.mark.unit


def _candidate(**overrides: object) -> LinuxSecurityCandidate:
    now = datetime.now(UTC)
    defaults: dict[str, object] = {
        "category": LinuxSecurityFindingCategory.BRUTE_FORCE,
        "severity": LinuxSecuritySeverity.CRITICAL,
        "subject": "1.2.3.4",
        "title": "t",
        "first_seen": now,
        "last_seen": now,
    }
    defaults.update(overrides)
    return LinuxSecurityCandidate(**defaults)  # type: ignore[arg-type]


def test_weights_must_sum_to_one() -> None:
    with pytest.raises(ValueError, match="sum to 1.0"):
        LinuxSecurityScoringWeights(
            detection_confidence=0.5,
            event_frequency=0.5,
            severity=0.5,
            evidence_quality=0.5,
            source_reliability=0.5,
            ioc_correlation=0.5,
            existing_findings=0.5,
        )


def test_default_weights_are_valid() -> None:
    LinuxSecurityScoringWeights()  # must not raise


def test_critical_severity_scores_higher_than_low() -> None:
    engine = LinuxThreatScoringEngine()
    critical = engine.score(
        _candidate(severity=LinuxSecuritySeverity.CRITICAL),
        detection_confidence=0.9,
        evidence_quality=0.9,
    )
    low = engine.score(
        _candidate(severity=LinuxSecuritySeverity.LOW),
        detection_confidence=0.9,
        evidence_quality=0.9,
    )
    assert critical.composite_score > low.composite_score


def test_composite_score_bounded() -> None:
    engine = LinuxThreatScoringEngine()
    score = engine.score(_candidate(), detection_confidence=1.0, evidence_quality=1.0)
    assert 0.0 <= score.composite_score <= 100.0


def test_score_candidates_applies_corroboration() -> None:
    engine = LinuxThreatScoringEngine()
    confidence_engine = LinuxSecurityConfidenceEngine()
    candidates = [_candidate(subject="1.2.3.4"), _candidate(subject="1.2.3.4")]
    scored = score_candidates(
        candidates,
        evidence_quality=0.9,
        confidence_engine=confidence_engine,
        scoring_engine=engine,
    )
    assert len(scored) == 2
    assert all(s.score.existing_findings > 0.0 for s in scored)


def test_score_candidates_empty_input() -> None:
    engine = LinuxThreatScoringEngine()
    confidence_engine = LinuxSecurityConfidenceEngine()
    assert (
        score_candidates(
            [], evidence_quality=1.0, confidence_engine=confidence_engine, scoring_engine=engine
        )
        == []
    )
