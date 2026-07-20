"""Unit tests for core/agents/mitre_mapping_agent.py — agent-level test
invoking the node function directly (constitution §11), independent of
graph orchestration and of the real vendored MITRE dataset (a small,
hand-built `MitreDataset` is injected instead, matching
tests/unit/_finding_test_helpers.make_dataset()'s established pattern)."""

from __future__ import annotations

import pytest
from tests.unit._finding_test_helpers import make_dataset

from core.agents.contracts import ExecutionStatus
from core.agents.mitre_mapping_agent import MitreMappingAgent
from core.graph.state import CaseInvestigationState
from core.knowledge.mitre.lookup import MitreLookup
from core.tools.mitre_tools import MitreMappingResolutionTool
from core.tools.registry import ToolRegistry

pytestmark = pytest.mark.unit


def _agent() -> MitreMappingAgent:
    registry = ToolRegistry()
    registry.register(MitreMappingResolutionTool(lookup=MitreLookup(make_dataset())))
    return MitreMappingAgent(tool_registry=registry)


def test_no_mapping_records_yet_is_degraded_unmapped_not_a_false_clean_bill() -> None:
    agent = _agent()
    state = CaseInvestigationState()
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    assert output.status == ExecutionStatus.DEGRADED
    assert output.output["summary"] is None


def test_resolves_hydrated_mitre_mapping_records() -> None:
    agent = _agent()
    state = CaseInvestigationState(
        mitre_mapping_records=[
            {
                "finding_id": "11111111-1111-1111-1111-111111111111",
                "technique_id": "T1110",
                "tactic_ids": ["TA0006"],
                "confidence": 0.75,
                "mapping_source": "rule_based",
                "attack_spec_version": "1.0-test",
            }
        ]
    )
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    assert output.status == ExecutionStatus.SUCCEEDED
    summary = output.output["summary"]
    assert summary["technique_count"] == 1
    assert summary["distinct_group_count"] == 1


def test_malformed_mapping_record_entries_are_skipped_not_crashed() -> None:
    agent = _agent()
    state = CaseInvestigationState(
        mitre_mapping_records=["not-a-dict", {"no_technique_id": True}, 42]
    )
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    assert output.status == ExecutionStatus.DEGRADED
    assert output.output["skipped_malformed_record_count"] == 3


def test_unknown_technique_id_is_reported_as_unresolved_not_dropped_silently() -> None:
    agent = _agent()
    state = CaseInvestigationState(
        mitre_mapping_records=[{"technique_id": "T9999", "confidence": 0.5}]
    )
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    assert output.status == ExecutionStatus.SUCCEEDED
    summary = output.output["summary"]
    assert summary["unresolved_technique_ids"] == ["T9999"]
    assert summary["technique_count"] == 0


def test_summary_appended_to_state_findings() -> None:
    agent = _agent()
    state = CaseInvestigationState(
        mitre_mapping_records=[{"technique_id": "T1110", "confidence": 0.5}]
    )
    result_state = agent(state)
    assert len(result_state.findings) == 1


def test_confidence_is_always_deterministic() -> None:
    agent = _agent()
    state = CaseInvestigationState(
        mitre_mapping_records=[{"technique_id": "T1110", "confidence": 0.5}]
    )
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    assert output.confidence.value == 1.0
