"""Unit tests for core/reporting/report_engine.py — the pipeline
orchestrator, including a determinism test and an oversized-input guard
test, mirroring
tests/unit/test_incident_response_response_plan_engine.py's established
pattern.
"""

from __future__ import annotations

import pytest

from core.reporting.exceptions import OversizedReportInputError
from core.reporting.inputs import ReportGenerationContext
from core.reporting.models import ReportType
from core.reporting.report_engine import ReportGenerationEngine

pytestmark = pytest.mark.unit


def test_generation_is_deterministic_given_the_same_input() -> None:
    context = ReportGenerationContext(
        case_id="c1",
        findings=({"finding_id": "f1", "title": "brute force", "severity": "high"},),
        mitre_mappings=({"technique_id": "T1110", "tactic_ids": ["TA0006"]},),
    )
    engine = ReportGenerationEngine()
    first = engine.generate(context=context, report_type=ReportType.TECHNICAL_INVESTIGATION)
    second = engine.generate(context=context, report_type=ReportType.TECHNICAL_INVESTIGATION)

    # `generation_duration_ms` is a timing artifact, not generation output —
    # excluded from the equality check the same way `plan_id`/`generated_at`
    # are excluded from `IncidentResponsePlan`'s determinism test.
    assert first.statistics.model_dump(exclude={"generation_duration_ms"}) == (
        second.statistics.model_dump(exclude={"generation_duration_ms"})
    )
    assert first.confidence == second.confidence
    assert first.degraded == second.degraded
    assert [s.content for s in first.sections] == [s.content for s in second.sections]


def test_empty_context_produces_degraded_report_never_a_crash() -> None:
    engine = ReportGenerationEngine()
    report = engine.generate(
        context=ReportGenerationContext(case_id="c1"), report_type=ReportType.EVIDENCE
    )
    assert report.degraded is True
    assert len(report.sections) > 0


def test_oversized_context_raises_oversized_report_input_error() -> None:
    engine = ReportGenerationEngine(max_records_per_report=2)
    context = ReportGenerationContext(
        case_id="c1",
        findings=({"title": "a"}, {"title": "b"}, {"title": "c"}),
    )
    with pytest.raises(OversizedReportInputError):
        engine.generate(context=context, report_type=ReportType.EVIDENCE)


def test_every_report_type_generates_without_raising() -> None:
    engine = ReportGenerationEngine()
    context = ReportGenerationContext(
        case_id="c1",
        findings=({"finding_id": "f1", "title": "x", "severity": "medium"},),
        iocs=({"ioc_type": "ipv4"},),
        mitre_mappings=({"technique_id": "T1110", "tactic_ids": ["TA0006"]},),
        incident_response_plan={"incident_severity": "medium", "recommendations": []},
    )
    for report_type in ReportType:
        report = engine.generate(context=context, report_type=report_type)
        assert report.report_type is report_type
        assert report.case_id == "c1"
