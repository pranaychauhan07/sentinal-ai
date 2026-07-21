"""Unit tests for core/agents/report_generator_agent.py — agent-level test
invoking the node function directly (constitution §11), independent of
graph orchestration, mirroring
tests/unit/test_agents_incident_response_agent.py's established pattern.
"""

from __future__ import annotations

import pytest

from core.agents.contracts import ExecutionStatus
from core.agents.report_generator_agent import (
    ReportGeneratorAgent,
    default_report_generator_agent_tool_registry,
)
from core.graph.state import CaseInvestigationState

pytestmark = pytest.mark.unit


def _agent() -> ReportGeneratorAgent:
    return ReportGeneratorAgent(tool_registry=default_report_generator_agent_tool_registry())


def test_no_data_anywhere_is_degraded_insufficient_evidence() -> None:
    agent = _agent()
    result_state = agent(CaseInvestigationState())
    output = result_state.agent_outputs[agent.name]
    assert output.status == ExecutionStatus.DEGRADED
    assert output.output["report"] is None


def test_generates_report_from_persisted_finding_records() -> None:
    agent = _agent()
    state = CaseInvestigationState(
        incident_response_finding_records=[
            {
                "finding_id": "11111111-1111-1111-1111-111111111111",
                "title": "Repeated failed SSH logins",
                "severity": "high",
                "risk_score": 70.0,
                "confidence": 0.9,
            }
        ]
    )
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    assert output.status == ExecutionStatus.SUCCEEDED
    report = output.output["report"]
    assert report is not None
    assert report["report_type"] == "technical_investigation"
    assert len(report["sections"]) > 0


def test_generates_report_from_mitre_mappings_only() -> None:
    agent = _agent()
    state = CaseInvestigationState(
        mitre_mapping_records=[{"technique_id": "T1110", "tactic_ids": ["TA0006"]}]
    )
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    assert output.output["report"] is not None


def test_malformed_records_are_skipped_not_crashed() -> None:
    agent = _agent()
    state = CaseInvestigationState(
        incident_response_finding_records=["not-a-dict", {"finding_id": "f1"}, 42]
    )
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    assert output.output["skipped_record_count"] == 2


def test_incident_response_plan_record_feeds_actions_section() -> None:
    agent = _agent()
    state = CaseInvestigationState(
        incident_response_finding_records=[{"finding_id": "f1", "title": "x", "severity": "high"}],
        incident_response_plan_record={
            "incident_severity": "high",
            "recommendations": [
                {
                    "action": {"title": "Isolate host", "category": "host_isolation"},
                    "priority": "p1_immediate",
                    "execution_order": 1,
                }
            ],
        },
    )
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    report = output.output["report"]
    ir_section = next(
        s for s in report["sections"] if s["section_type"] == "incident_response_actions"
    )
    assert ir_section["content"]["has_plan"] is True
