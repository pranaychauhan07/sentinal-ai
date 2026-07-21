"""Unit tests for core/incident_response/risk_prioritizer.py."""

from __future__ import annotations

import pytest

from core.incident_response.inputs import IncidentInputFinding
from core.incident_response.models import IncidentSeverity, ResponseCategory, ResponsePriority
from core.incident_response.risk_prioritizer import RiskPrioritizer

pytestmark = pytest.mark.unit


def test_critical_finding_escalates_priority_toward_p1() -> None:
    prioritizer = RiskPrioritizer()
    finding = IncidentInputFinding(finding_id="f1", severity=IncidentSeverity.CRITICAL)
    recommendation = prioritizer.prioritize(finding, ResponseCategory.PATCH_PRIORITIZATION)
    # PATCH_PRIORITIZATION's base priority is P4_MEDIUM; CRITICAL escalates one step.
    assert recommendation.priority == ResponsePriority.P3_HIGH


def test_low_severity_finding_deescalates_priority() -> None:
    prioritizer = RiskPrioritizer()
    finding = IncidentInputFinding(finding_id="f1", severity=IncidentSeverity.LOW)
    recommendation = prioritizer.prioritize(finding, ResponseCategory.HOST_ISOLATION)
    # HOST_ISOLATION's base priority is P1_IMMEDIATE; LOW de-escalates one step.
    assert recommendation.priority == ResponsePriority.P2_URGENT


def test_medium_severity_uses_template_base_priority_unchanged() -> None:
    prioritizer = RiskPrioritizer()
    finding = IncidentInputFinding(finding_id="f1", severity=IncidentSeverity.MEDIUM)
    recommendation = prioritizer.prioritize(finding, ResponseCategory.HOST_ISOLATION)
    assert recommendation.priority == ResponsePriority.P1_IMMEDIATE


def test_risk_score_falls_back_to_severity_default_when_finding_has_none() -> None:
    prioritizer = RiskPrioritizer()
    finding = IncidentInputFinding(finding_id="f1", severity=IncidentSeverity.CRITICAL)
    recommendation = prioritizer.prioritize(finding, ResponseCategory.HOST_ISOLATION)
    assert recommendation.risk_score == 90.0


def test_risk_score_uses_findings_own_value_when_present() -> None:
    prioritizer = RiskPrioritizer()
    finding = IncidentInputFinding(
        finding_id="f1", severity=IncidentSeverity.CRITICAL, risk_score=42.0
    )
    recommendation = prioritizer.prioritize(finding, ResponseCategory.HOST_ISOLATION)
    assert recommendation.risk_score == 42.0


def test_required_evidence_and_supporting_finding_ids_populated() -> None:
    prioritizer = RiskPrioritizer()
    finding = IncidentInputFinding(
        finding_id="f1", source="finding", title="Suspicious login", severity=IncidentSeverity.HIGH
    )
    recommendation = prioritizer.prioritize(finding, ResponseCategory.HOST_ISOLATION)
    assert recommendation.supporting_finding_ids == ("f1",)
    assert len(recommendation.required_evidence) == 1
    assert recommendation.required_evidence[0].finding_id == "f1"
    assert recommendation.required_evidence[0].source == "finding"


def test_mitre_technique_ids_propagated_from_finding() -> None:
    prioritizer = RiskPrioritizer()
    finding = IncidentInputFinding(
        finding_id="f1", severity=IncidentSeverity.HIGH, mitre_technique_ids=("T1110",)
    )
    recommendation = prioritizer.prioritize(finding, ResponseCategory.HOST_ISOLATION)
    assert recommendation.mitre_technique_ids == ("T1110",)
