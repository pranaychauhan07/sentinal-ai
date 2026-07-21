"""Unit tests for core/agents/memory_agent.py — agent-level test invoking
the node function directly (constitution §11), independent of graph
orchestration and of any real vector-store/knowledge-layer backend (this
agent never touches either itself — ADR-0028 §1)."""

from __future__ import annotations

import pytest

from core.agents.contracts import ExecutionStatus
from core.agents.memory_agent import MemoryAgent, default_memory_agent_tool_registry
from core.graph.state import CaseInvestigationState

pytestmark = pytest.mark.unit


def _agent() -> MemoryAgent:
    return MemoryAgent(tool_registry=default_memory_agent_tool_registry())


def test_no_memory_context_record_is_degraded_not_failed() -> None:
    agent = _agent()
    state = CaseInvestigationState()
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    assert output.status == ExecutionStatus.DEGRADED
    assert output.output["context"] is None


def test_resolves_hydrated_memory_context_record() -> None:
    agent = _agent()
    state = CaseInvestigationState(
        memory_context_record={
            "query_text": "brute force ssh login",
            "similar_findings": [
                {
                    "case_id": "11111111-1111-1111-1111-111111111111",
                    "record_id": "22222222-2222-2222-2222-222222222222",
                    "score": 0.8,
                    "excerpt": "repeated failed logins",
                    "category": "finding",
                    "recorded_at": None,
                }
            ],
            "similar_cases": [],
            "similar_iocs": [],
            "similar_mitre_techniques": [],
            "similar_reports": [],
            "related_knowledge": [],
            "category_metrics": [{"category": "finding", "raw_candidate_count": 1}],
            "min_similarity": 0.35,
            "top_k_per_category": 5,
            "degraded": False,
        }
    )
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    assert output.status == ExecutionStatus.SUCCEEDED
    context = output.output["context"]
    assert len(context["similar_findings"]) == 1
    assert context["metrics"]["hit"] is True
    assert len(result_state.findings) == 1


def test_empty_query_text_is_degraded_insufficient_signal() -> None:
    agent = _agent()
    state = CaseInvestigationState(
        memory_context_record={
            "query_text": "",
            "similar_cases": [],
            "similar_findings": [],
            "similar_iocs": [],
            "similar_mitre_techniques": [],
            "similar_reports": [],
            "related_knowledge": [],
            "category_metrics": [],
            "degraded": True,
        }
    )
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    assert output.status == ExecutionStatus.DEGRADED
    assert output.output["context"]["metrics"]["query_text_empty"] is True


def test_no_matches_found_is_succeeded_clean_bill_not_degraded() -> None:
    agent = _agent()
    state = CaseInvestigationState(
        memory_context_record={
            "query_text": "novel attack pattern never seen before",
            "similar_cases": [],
            "similar_findings": [],
            "similar_iocs": [],
            "similar_mitre_techniques": [],
            "similar_reports": [],
            "related_knowledge": [],
            "category_metrics": [{"category": "finding", "raw_candidate_count": 0}],
            "degraded": False,
        }
    )
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    assert output.status == ExecutionStatus.SUCCEEDED
    assert "clean bill" in output.thought


def test_malformed_record_entries_are_skipped_not_crashed() -> None:
    agent = _agent()
    state = CaseInvestigationState(
        memory_context_record={
            "query_text": "query",
            "similar_findings": ["not-a-dict", {"missing": "fields"}],
            "similar_cases": [],
            "similar_iocs": [],
            "similar_mitre_techniques": [],
            "similar_reports": [],
            "related_knowledge": [],
            "category_metrics": [],
        }
    )
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    assert output.output["skipped_malformed_item_count"] == 2
    assert "malformed" in output.thought


def test_confidence_is_always_deterministic() -> None:
    agent = _agent()
    state = CaseInvestigationState(memory_context_record={"query_text": "query"})
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    assert output.confidence.value == 1.0
