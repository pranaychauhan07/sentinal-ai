"""Unit tests for core/agents/threat_hunter_agent.py — agent-level test
invoking the node function directly (constitution §11), independent of
graph orchestration. Mirrors tests/unit/test_agents_vulnerability.py's
pattern exactly."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from core.agents.contracts import ExecutionStatus
from core.agents.threat_hunter_agent import (
    ThreatHunterAgent,
    default_threat_hunter_agent_tool_registry,
)
from core.graph.state import CaseInvestigationState
from core.parsers.models import ChainOfCustody, EvidenceType, NormalizedEvidence

pytestmark = pytest.mark.unit


def _custody() -> ChainOfCustody:
    return ChainOfCustody(
        ingested_at=datetime.now(UTC),
        ingested_by="tester",
        original_filename="auth.log",
        sha256="a" * 64,
        file_size_bytes=100,
    )


def _hunting_evidence(evidence_type: EvidenceType = EvidenceType.SSH_AUTH) -> NormalizedEvidence:
    return NormalizedEvidence(
        evidence_type=evidence_type,
        source="auth.log",
        parser_name="ssh_auth",
        parser_version="1.0.0",
        confidence=1.0,
        records=[],
        chain_of_custody=_custody(),
    )


def _agent() -> ThreatHunterAgent:
    return ThreatHunterAgent(tool_registry=default_threat_hunter_agent_tool_registry())


def test_no_evidence_is_degraded_not_a_false_clean_bill() -> None:
    agent = _agent()
    state = CaseInvestigationState()
    result = agent(state)
    assert result.agent_outputs[agent.name].status == ExecutionStatus.DEGRADED


def test_non_hunting_evidence_is_skipped_not_analyzed() -> None:
    agent = _agent()
    scan_evidence = NormalizedEvidence(
        evidence_type=EvidenceType.NESSUS_XML,
        source="scan.nessus",
        parser_name="nessus_xml",
        parser_version="1.0.0",
        confidence=1.0,
        records=[],
        chain_of_custody=_custody(),
    )
    state = CaseInvestigationState(evidence=[scan_evidence])
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    assert output.status == ExecutionStatus.DEGRADED
    assert output.output["skipped_non_hunting_items"] == 1


def test_summarizes_hydrated_linux_security_records() -> None:
    agent = _agent()
    state = CaseInvestigationState(
        evidence=[_hunting_evidence()],
        linux_security_records=[
            {
                "category": "brute_force",
                "subject": "203.0.113.44",
                "subject_type": "ip",
                "title": "SSH brute force",
                "severity": "high",
                "composite_score": 80.0,
                "occurrence_count": 6,
            },
            {
                "category": "root_login",
                "subject": "203.0.113.44",
                "subject_type": "ip",
                "title": "Root login",
                "severity": "high",
                "composite_score": 60.0,
                "occurrence_count": 1,
            },
        ],
    )
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    assert output.status == ExecutionStatus.SUCCEEDED
    report = output.output["report"]
    assert report["finding_count"] == 2
    assert report["category_counts"] == {"brute_force": 1, "root_login": 1}
    assert report["highest_composite_score"] == 80.0
    assert report["distinct_subject_count"] == 1
    assert "brute_force" in report["narrative"]


def test_malformed_linux_security_record_entries_are_skipped_not_crashed() -> None:
    agent = _agent()
    state = CaseInvestigationState(
        evidence=[_hunting_evidence()],
        linux_security_records=["not-a-dict", {"unexpected_key_only": True}, 42],
    )
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    assert output.status == ExecutionStatus.SUCCEEDED
    assert output.output["report"]["finding_count"] >= 0


def test_no_findings_yet_still_succeeds_with_zero_summary() -> None:
    agent = _agent()
    state = CaseInvestigationState(evidence=[_hunting_evidence()], linux_security_records=[])
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    assert output.status == ExecutionStatus.SUCCEEDED
    assert output.output["report"]["finding_count"] == 0
    assert "No Linux security findings" in output.output["report"]["narrative"]


def test_findings_are_appended_to_state_findings() -> None:
    agent = _agent()
    state = CaseInvestigationState(evidence=[_hunting_evidence()], linux_security_records=[])
    result_state = agent(state)
    assert len(result_state.findings) == 1


def test_confidence_is_always_deterministic() -> None:
    agent = _agent()
    state = CaseInvestigationState(
        case_id=uuid.uuid4(), evidence=[_hunting_evidence()], linux_security_records=[]
    )
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    assert output.confidence.value == 1.0


def test_syslog_evidence_type_also_recognized() -> None:
    agent = _agent()
    state = CaseInvestigationState(
        evidence=[_hunting_evidence(EvidenceType.SYSLOG)], linux_security_records=[]
    )
    result_state = agent(state)
    assert result_state.agent_outputs[agent.name].status == ExecutionStatus.SUCCEEDED
