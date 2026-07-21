"""Unit tests for core/tools/ir_tools.py."""

from __future__ import annotations

import pytest

from core.incident_response.inputs import IncidentInputFinding
from core.incident_response.models import IncidentSeverity
from core.tools.ir_tools import (
    IncidentResponsePlanGenerationInput,
    IncidentResponsePlanGenerationOutput,
    IncidentResponsePlanGenerationTool,
)

pytestmark = pytest.mark.unit


def test_generates_a_plan_from_findings() -> None:
    tool = IncidentResponsePlanGenerationTool()
    result = tool(
        IncidentResponsePlanGenerationInput(
            case_id="c1",
            findings=[
                IncidentInputFinding(
                    finding_id="f1",
                    severity=IncidentSeverity.HIGH,
                    mitre_tactic_ids=("TA0006",),
                )
            ],
        )
    )
    assert isinstance(result, IncidentResponsePlanGenerationOutput)
    assert result.plan.case_id == "c1"
    assert len(result.plan.recommendations) > 0


def test_empty_findings_returns_degraded_plan() -> None:
    tool = IncidentResponsePlanGenerationTool()
    result = tool(IncidentResponsePlanGenerationInput(case_id="c1", findings=[]))
    assert result.plan.plan_degraded is True


def test_deterministic_given_same_input() -> None:
    tool = IncidentResponsePlanGenerationTool()
    arguments = IncidentResponsePlanGenerationInput(
        case_id="c1",
        findings=[
            IncidentInputFinding(
                finding_id="f1", severity=IncidentSeverity.CRITICAL, title="malware"
            )
        ],
    )
    first = tool(arguments)
    second = tool(arguments)
    assert [r.model_dump(exclude={"recommendation_id"}) for r in first.plan.recommendations] == [
        r.model_dump(exclude={"recommendation_id"}) for r in second.plan.recommendations
    ]
