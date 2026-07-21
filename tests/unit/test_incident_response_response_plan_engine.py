"""Unit tests for core/incident_response/response_plan_engine.py — the
package's pipeline orchestrator."""

from __future__ import annotations

import pytest

from core.incident_response.exceptions import OversizedFindingSetError
from core.incident_response.inputs import IncidentInputFinding
from core.incident_response.models import IncidentSeverity
from core.incident_response.response_plan_engine import ResponsePlanEngine

pytestmark = pytest.mark.unit


def test_empty_findings_returns_degraded_zero_recommendation_plan() -> None:
    engine = ResponsePlanEngine()
    plan = engine.generate(case_id="c1", findings=[])
    assert plan.plan_degraded is True
    assert plan.recommendations == ()
    assert plan.incident_severity == IncidentSeverity.INFO
    assert "insufficient evidence" in plan.degraded_reason.lower()


def test_generates_recommendations_from_a_mapped_finding() -> None:
    engine = ResponsePlanEngine()
    findings = [
        IncidentInputFinding(
            finding_id="f1",
            source="finding",
            title="Repeated failed SSH logins",
            severity=IncidentSeverity.HIGH,
            risk_score=70.0,
            confidence=0.9,
            mitre_technique_ids=("T1110",),
            mitre_tactic_ids=("TA0006",),
        )
    ]
    plan = engine.generate(case_id="c1", findings=findings)
    assert plan.plan_degraded is False
    assert len(plan.recommendations) > 0
    assert plan.incident_severity == IncidentSeverity.HIGH
    assert plan.metrics.finding_count_considered == 1
    assert plan.metrics.mitre_technique_count == 1


def test_finding_matching_no_category_yields_degraded_plan() -> None:
    engine = ResponsePlanEngine()
    findings = [
        IncidentInputFinding(finding_id="f1", severity=IncidentSeverity.INFO, title="routine")
    ]
    plan = engine.generate(case_id="c1", findings=findings)
    assert plan.plan_degraded is True
    assert plan.recommendations == ()


def test_generation_is_deterministic_given_the_same_input() -> None:
    engine = ResponsePlanEngine()
    findings = [
        IncidentInputFinding(
            finding_id="f1", severity=IncidentSeverity.CRITICAL, title="malware detected"
        ),
        IncidentInputFinding(
            finding_id="f2", severity=IncidentSeverity.HIGH, mitre_tactic_ids=("TA0011",)
        ),
    ]
    plan_a = engine.generate(case_id="c1", findings=findings)
    plan_b = engine.generate(case_id="c1", findings=findings)
    dump_a = [r.model_dump(exclude={"recommendation_id"}) for r in plan_a.recommendations]
    dump_b = [r.model_dump(exclude={"recommendation_id"}) for r in plan_b.recommendations]
    assert dump_a == dump_b


def test_oversized_finding_set_raises() -> None:
    engine = ResponsePlanEngine(max_findings_per_plan=2)
    findings = [
        IncidentInputFinding(finding_id=str(i), severity=IncidentSeverity.LOW) for i in range(3)
    ]
    with pytest.raises(OversizedFindingSetError):
        engine.generate(case_id="c1", findings=findings)


def test_lessons_learned_always_includes_the_baseline_entry() -> None:
    engine = ResponsePlanEngine()
    findings = [
        IncidentInputFinding(
            finding_id="f1", severity=IncidentSeverity.CRITICAL, title="malware ransomware"
        )
    ]
    plan = engine.generate(case_id="c1", findings=findings)
    assert any("post-incident review" in lesson for lesson in plan.lessons_learned)


def test_skipped_record_count_discounts_overall_confidence() -> None:
    engine = ResponsePlanEngine()
    findings = [
        IncidentInputFinding(
            finding_id="f1", severity=IncidentSeverity.HIGH, mitre_tactic_ids=("TA0006",)
        )
    ]
    clean_plan = engine.generate(case_id="c1", findings=findings, skipped_record_count=0)
    degraded_plan = engine.generate(case_id="c1", findings=findings, skipped_record_count=1)
    assert degraded_plan.overall_confidence < clean_plan.overall_confidence
