"""Unit tests for core/agents/owasp_security_agent.py — agent-level test
invoking the node function directly (constitution §11), independent of
graph orchestration."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from core.agents.contracts import ExecutionStatus
from core.agents.owasp_security_agent import (
    OwaspSecurityAgent,
    default_owasp_security_agent_tool_registry,
)
from core.graph.state import CaseInvestigationState
from core.parsers.models import ChainOfCustody, EvidenceType, NormalizedEvidence

pytestmark = pytest.mark.unit


def _custody() -> ChainOfCustody:
    return ChainOfCustody(
        ingested_at=datetime.now(UTC),
        ingested_by="tester",
        original_filename="app.py",
        sha256="a" * 64,
        file_size_bytes=100,
    )


def _source_evidence(evidence_type: EvidenceType = EvidenceType.SOURCE_CODE) -> NormalizedEvidence:
    return NormalizedEvidence(
        evidence_type=evidence_type,
        source="app.py",
        parser_name="source_code",
        parser_version="1.0.0",
        confidence=1.0,
        records=[],
        chain_of_custody=_custody(),
    )


def _agent() -> OwaspSecurityAgent:
    return OwaspSecurityAgent(tool_registry=default_owasp_security_agent_tool_registry())


def test_no_evidence_is_degraded_not_a_false_clean_bill() -> None:
    agent = _agent()
    state = CaseInvestigationState()
    result_state = agent(state)
    assert result_state.agent_outputs[agent.name].status == ExecutionStatus.DEGRADED


def test_non_source_evidence_is_skipped_not_analyzed() -> None:
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
    assert output.output["skipped_non_source_items"] == 1


def test_summarizes_hydrated_owasp_security_records() -> None:
    agent = _agent()
    state = CaseInvestigationState(
        evidence=[_source_evidence()],
        owasp_security_records=[
            {
                "kind": "finding",
                "category": "sql_injection",
                "owasp_category": "a03_injection",
                "cwe_id": "CWE-89",
                "severity": "high",
                "confidence": 0.8,
                "evidence_reference": "app.py:5",
                "explanation": "dynamic query",
                "recommended_remediation": "parameterize",
                "source": "python_ast_analyzer",
            },
            {
                "kind": "summary",
                "language": "python",
                "overall_risk_level": "high",
                "overall_confidence": 0.8,
                "overall_explanation": "1 finding",
                "parse_degraded": False,
            },
        ],
    )
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    assert output.status == ExecutionStatus.SUCCEEDED
    advice = output.output["advice"]
    assert advice["finding_count"] == 1
    assert advice["language"] == "python"
    assert advice["overall_risk_level"] == "high"


def test_malformed_owasp_security_record_entries_are_skipped_not_crashed() -> None:
    agent = _agent()
    state = CaseInvestigationState(
        evidence=[_source_evidence()],
        owasp_security_records=["not-a-dict", {"kind": "finding"}, 42],
    )
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    assert output.status == ExecutionStatus.SUCCEEDED


def test_no_records_yet_still_succeeds_with_zero_summary() -> None:
    agent = _agent()
    state = CaseInvestigationState(evidence=[_source_evidence()], owasp_security_records=[])
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    assert output.status == ExecutionStatus.SUCCEEDED
    assert output.output["advice"]["finding_count"] == 0


def test_advice_appended_to_state_findings() -> None:
    agent = _agent()
    state = CaseInvestigationState(evidence=[_source_evidence()], owasp_security_records=[])
    result_state = agent(state)
    assert len(result_state.findings) == 1


def test_confidence_is_always_deterministic() -> None:
    agent = _agent()
    state = CaseInvestigationState(evidence=[_source_evidence()], owasp_security_records=[])
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    assert output.confidence.value == 1.0
