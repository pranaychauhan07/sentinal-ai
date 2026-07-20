"""Unit tests for core/linux_security/finding_generator.py."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from core.linux_security.finding_generator import LinuxSecurityFindingGenerator
from core.linux_security.models import (
    LinuxSecurityCandidate,
    LinuxSecurityFindingCategory,
    LinuxSecurityScore,
    LinuxSecuritySeverity,
    ScoredLinuxSecurityCandidate,
)

pytestmark = pytest.mark.unit

_NOW = datetime(2026, 7, 18, 10, 0, 0, tzinfo=UTC)


def _scored(
    category: LinuxSecurityFindingCategory,
    subject: str,
    *,
    severity: LinuxSecuritySeverity = LinuxSecuritySeverity.HIGH,
    composite_score: float = 50.0,
    line_number: int | None = None,
    seconds: int = 0,
) -> ScoredLinuxSecurityCandidate:
    candidate = LinuxSecurityCandidate(
        category=category,
        severity=severity,
        subject=subject,
        title=f"{category.value} on {subject}",
        first_seen=_NOW + timedelta(seconds=seconds),
        last_seen=_NOW + timedelta(seconds=seconds),
        line_numbers=(line_number,) if line_number is not None else (),
    )
    score = LinuxSecurityScore(
        detection_confidence=0.9,
        event_frequency=0.5,
        severity_weight=0.75,
        evidence_quality=0.9,
        source_reliability=0.8,
        ioc_correlation=0.0,
        existing_findings=0.0,
        composite_score=composite_score,
    )
    return ScoredLinuxSecurityCandidate(candidate=candidate, score=score)


def test_groups_by_category_and_subject() -> None:
    scored = [
        _scored(LinuxSecurityFindingCategory.BRUTE_FORCE, "1.2.3.4", composite_score=40.0),
        _scored(LinuxSecurityFindingCategory.BRUTE_FORCE, "1.2.3.4", composite_score=80.0),
        _scored(LinuxSecurityFindingCategory.BRUTE_FORCE, "5.6.7.8", composite_score=20.0),
    ]
    findings = LinuxSecurityFindingGenerator().generate(scored)
    assert len(findings) == 2
    ip1 = next(f for f in findings if f.subject == "1.2.3.4")
    assert ip1.composite_score == 80.0  # highest of the group
    assert ip1.occurrence_count == 2


def test_different_categories_not_merged() -> None:
    scored = [
        _scored(LinuxSecurityFindingCategory.BRUTE_FORCE, "1.2.3.4"),
        _scored(LinuxSecurityFindingCategory.ROOT_LOGIN, "1.2.3.4"),
    ]
    findings = LinuxSecurityFindingGenerator().generate(scored)
    assert len(findings) == 2


def test_line_numbers_deduplicated_and_preserved() -> None:
    scored = [
        _scored(LinuxSecurityFindingCategory.BRUTE_FORCE, "1.2.3.4", line_number=5),
        _scored(LinuxSecurityFindingCategory.BRUTE_FORCE, "1.2.3.4", line_number=5),
        _scored(LinuxSecurityFindingCategory.BRUTE_FORCE, "1.2.3.4", line_number=6),
    ]
    findings = LinuxSecurityFindingGenerator().generate(scored)
    assert findings[0].line_numbers == (5, 6)


def test_first_and_last_seen_span_the_group() -> None:
    scored = [
        _scored(LinuxSecurityFindingCategory.BRUTE_FORCE, "1.2.3.4", seconds=0),
        _scored(LinuxSecurityFindingCategory.BRUTE_FORCE, "1.2.3.4", seconds=100),
    ]
    findings = LinuxSecurityFindingGenerator().generate(scored)
    assert findings[0].first_seen == _NOW
    assert findings[0].last_seen == _NOW + timedelta(seconds=100)


def test_empty_input_returns_empty() -> None:
    assert LinuxSecurityFindingGenerator().generate([]) == []
