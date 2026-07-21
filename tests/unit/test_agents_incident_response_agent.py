"""Unit tests for core/agents/incident_response_agent.py — agent-level test
invoking the node function directly (constitution §11), independent of
graph orchestration, mirroring
tests/unit/test_agents_mitre_mapping_agent.py's established pattern."""

from __future__ import annotations

import pytest

from core.agents.contracts import ExecutionStatus
from core.agents.incident_response_agent import (
    IncidentResponseAgent,
    default_incident_response_agent_tool_registry,
)
from core.graph.state import CaseInvestigationState

pytestmark = pytest.mark.unit


def _agent() -> IncidentResponseAgent:
    return IncidentResponseAgent(tool_registry=default_incident_response_agent_tool_registry())


def test_no_records_anywhere_is_degraded_insufficient_evidence() -> None:
    agent = _agent()
    result_state = agent(CaseInvestigationState())
    output = result_state.agent_outputs[agent.name]
    assert output.status == ExecutionStatus.DEGRADED
    assert output.output["plan"] is None


def test_synthesizes_plan_from_persisted_finding_records() -> None:
    agent = _agent()
    state = CaseInvestigationState(
        incident_response_finding_records=[
            {
                "finding_id": "11111111-1111-1111-1111-111111111111",
                "title": "Repeated failed SSH logins",
                "severity": "high",
                "risk_score": 70.0,
                "confidence": 0.9,
                "mitre_technique_ids": ["T1110"],
                "mitre_tactic_ids": ["TA0006"],
            }
        ]
    )
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    assert output.status == ExecutionStatus.SUCCEEDED
    plan = output.output["plan"]
    assert plan is not None
    assert len(plan["recommendations"]) > 0
    assert plan["incident_severity"] == "high"


def test_synthesizes_plan_from_vulnerability_records() -> None:
    agent = _agent()
    state = CaseInvestigationState(
        vulnerability_records=[
            {
                "cve_id": "CVE-2024-1234",
                "plugin_id": "12345",
                "title": "Exploitable remote code execution",
                "severity": "critical",
                "priority": "p1_critical",
                "composite_score": 95.0,
                "affected_asset_ids": ["host-01"],
            }
        ]
    )
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    assert output.status == ExecutionStatus.SUCCEEDED
    plan = output.output["plan"]
    assert any(r["action"]["category"] == "patch_prioritization" for r in plan["recommendations"])


def test_malformed_records_are_skipped_not_crashed() -> None:
    agent = _agent()
    state = CaseInvestigationState(
        incident_response_finding_records=["not-a-dict", {"finding_id": "f1"}, 42]
    )
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    # {"finding_id": "f1"} is a well-formed (if minimal) dict -> yields an
    # INFO-severity finding with no title, which itself matches no category
    # and results in a degraded, zero-recommendation plan; the two malformed
    # entries are skipped, never crashing the agent.
    assert output.status == ExecutionStatus.DEGRADED
    assert output.output["skipped_record_count"] == 2


def test_plan_appended_to_state_findings() -> None:
    agent = _agent()
    state = CaseInvestigationState(
        incident_response_finding_records=[
            {"finding_id": "f1", "title": "malware detected", "severity": "critical"}
        ]
    )
    result_state = agent(state)
    assert len(result_state.findings) == 1
