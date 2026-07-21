"""Unit tests for core/incident_response/severity_classifier.py."""

from __future__ import annotations

import pytest

from core.incident_response.inputs import IncidentInputFinding
from core.incident_response.models import IncidentSeverity
from core.incident_response.severity_classifier import (
    IncidentSeverityClassifier,
    SeverityClassificationWeights,
)

pytestmark = pytest.mark.unit


def _finding(severity: IncidentSeverity) -> IncidentInputFinding:
    return IncidentInputFinding(finding_id="f", severity=severity)


def test_no_findings_is_info() -> None:
    classifier = IncidentSeverityClassifier()
    result = classifier.classify([])
    assert result.severity == IncidentSeverity.INFO
    assert result.qualifying_finding_count == 0
    assert result.escalation_steps == 0
    assert result.justification


def test_single_finding_matches_its_own_severity() -> None:
    classifier = IncidentSeverityClassifier()
    result = classifier.classify([_finding(IncidentSeverity.HIGH)])
    assert result.severity == IncidentSeverity.HIGH
    assert result.base_severity == IncidentSeverity.HIGH
    assert result.escalation_steps == 0


def test_escalates_after_enough_medium_or_above_findings() -> None:
    weights = SeverityClassificationWeights(escalation_finding_count=3)
    classifier = IncidentSeverityClassifier(weights=weights)
    findings = [_finding(IncidentSeverity.MEDIUM) for _ in range(3)]
    result = classifier.classify(findings)
    assert result.severity == IncidentSeverity.HIGH
    assert result.base_severity == IncidentSeverity.MEDIUM
    assert result.qualifying_finding_count == 3
    assert result.escalation_steps == 1
    assert "escalated 1 level" in result.justification
    assert "3 finding(s)" in result.justification


def test_double_escalation_caps_at_critical() -> None:
    weights = SeverityClassificationWeights(
        escalation_finding_count=3, double_escalation_finding_count=6
    )
    classifier = IncidentSeverityClassifier(weights=weights)
    findings = [_finding(IncidentSeverity.MEDIUM) for _ in range(6)]
    result = classifier.classify(findings)
    assert result.severity == IncidentSeverity.CRITICAL
    assert result.escalation_steps == 2
    assert "escalated 2 level" in result.justification


def test_critical_never_escalates_past_critical() -> None:
    weights = SeverityClassificationWeights(escalation_finding_count=2)
    classifier = IncidentSeverityClassifier(weights=weights)
    findings = [_finding(IncidentSeverity.CRITICAL) for _ in range(5)]
    result = classifier.classify(findings)
    assert result.severity == IncidentSeverity.CRITICAL
    assert result.base_severity == IncidentSeverity.CRITICAL


def test_low_severity_findings_below_threshold_do_not_escalate() -> None:
    classifier = IncidentSeverityClassifier()
    findings = [_finding(IncidentSeverity.LOW) for _ in range(10)]
    result = classifier.classify(findings)
    assert result.severity == IncidentSeverity.LOW
    assert result.escalation_steps == 0
    assert "no escalation was applied" in result.justification


def test_justification_names_escalation_threshold_when_not_met() -> None:
    weights = SeverityClassificationWeights(escalation_finding_count=5)
    classifier = IncidentSeverityClassifier(weights=weights)
    findings = [_finding(IncidentSeverity.MEDIUM) for _ in range(2)]
    result = classifier.classify(findings)
    assert result.escalation_steps == 0
    assert "2 finding(s)" in result.justification
