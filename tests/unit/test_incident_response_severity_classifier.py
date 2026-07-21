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
    assert classifier.classify([]) == IncidentSeverity.INFO


def test_single_finding_matches_its_own_severity() -> None:
    classifier = IncidentSeverityClassifier()
    assert classifier.classify([_finding(IncidentSeverity.HIGH)]) == IncidentSeverity.HIGH


def test_escalates_after_enough_medium_or_above_findings() -> None:
    weights = SeverityClassificationWeights(escalation_finding_count=3)
    classifier = IncidentSeverityClassifier(weights=weights)
    findings = [_finding(IncidentSeverity.MEDIUM) for _ in range(3)]
    assert classifier.classify(findings) == IncidentSeverity.HIGH


def test_double_escalation_caps_at_critical() -> None:
    weights = SeverityClassificationWeights(
        escalation_finding_count=3, double_escalation_finding_count=6
    )
    classifier = IncidentSeverityClassifier(weights=weights)
    findings = [_finding(IncidentSeverity.MEDIUM) for _ in range(6)]
    assert classifier.classify(findings) == IncidentSeverity.CRITICAL


def test_critical_never_escalates_past_critical() -> None:
    weights = SeverityClassificationWeights(escalation_finding_count=2)
    classifier = IncidentSeverityClassifier(weights=weights)
    findings = [_finding(IncidentSeverity.CRITICAL) for _ in range(5)]
    assert classifier.classify(findings) == IncidentSeverity.CRITICAL


def test_low_severity_findings_below_threshold_do_not_escalate() -> None:
    classifier = IncidentSeverityClassifier()
    findings = [_finding(IncidentSeverity.LOW) for _ in range(10)]
    assert classifier.classify(findings) == IncidentSeverity.LOW
