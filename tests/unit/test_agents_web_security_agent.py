"""Unit tests for core/agents/web_security_agent.py — agent-level test
invoking the node function directly (constitution §11), independent of
graph orchestration."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from core.agents.contracts import ExecutionStatus
from core.agents.web_security_agent import (
    WebSecurityAgent,
    default_web_security_agent_tool_registry,
)
from core.graph.state import CaseInvestigationState
from core.parsers.models import ChainOfCustody, EvidenceType, NormalizedEvidence

pytestmark = pytest.mark.unit


def _custody() -> ChainOfCustody:
    return ChainOfCustody(
        ingested_at=datetime.now(UTC),
        ingested_by="tester",
        original_filename="transaction.txt",
        sha256="a" * 64,
        file_size_bytes=100,
    )


def _http_evidence(
    evidence_type: EvidenceType = EvidenceType.HTTP_TRANSACTION,
) -> NormalizedEvidence:
    return NormalizedEvidence(
        evidence_type=evidence_type,
        source="transaction.txt",
        parser_name="http_transaction",
        parser_version="1.0.0",
        confidence=1.0,
        records=[],
        chain_of_custody=_custody(),
    )


def _agent() -> WebSecurityAgent:
    return WebSecurityAgent(tool_registry=default_web_security_agent_tool_registry())


def test_no_evidence_is_degraded_not_a_false_clean_bill() -> None:
    agent = _agent()
    state = CaseInvestigationState()
    result_state = agent(state)
    assert result_state.agent_outputs[agent.name].status == ExecutionStatus.DEGRADED


def test_non_http_evidence_is_skipped_not_analyzed() -> None:
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
    assert output.output["skipped_non_http_items"] == 1


def test_summarizes_hydrated_owasp_web_records() -> None:
    agent = _agent()
    state = CaseInvestigationState(
        evidence=[_http_evidence()],
        owasp_web_records=[
            {
                "kind": "finding",
                "category": "a02_cryptographic_failures",
                "severity": "critical",
                "confidence": 0.9,
                "evidence_reference": "jwt-token",
                "explanation": "alg none",
                "recommended_remediation": "reject",
                "source": "jwt_analyzer",
            },
            {
                "kind": "summary",
                "overall_risk_level": "critical",
                "overall_confidence": 0.9,
                "overall_explanation": "1 finding",
                "skipped_line_count": 0,
            },
        ],
    )
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    assert output.status == ExecutionStatus.SUCCEEDED
    advice = output.output["advice"]
    assert advice["finding_count"] == 1
    assert advice["overall_risk_level"] == "critical"


def test_malformed_owasp_web_record_entries_are_skipped_not_crashed() -> None:
    agent = _agent()
    state = CaseInvestigationState(
        evidence=[_http_evidence()],
        owasp_web_records=["not-a-dict", {"kind": "finding"}, 42],
    )
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    assert output.status == ExecutionStatus.SUCCEEDED


def test_no_records_yet_still_succeeds_with_zero_summary() -> None:
    agent = _agent()
    state = CaseInvestigationState(evidence=[_http_evidence()], owasp_web_records=[])
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    assert output.status == ExecutionStatus.SUCCEEDED
    assert output.output["advice"]["finding_count"] == 0


def test_advice_appended_to_state_findings() -> None:
    agent = _agent()
    state = CaseInvestigationState(evidence=[_http_evidence()], owasp_web_records=[])
    result_state = agent(state)
    assert len(result_state.findings) == 1


def test_confidence_is_always_deterministic() -> None:
    agent = _agent()
    state = CaseInvestigationState(evidence=[_http_evidence()], owasp_web_records=[])
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    assert output.confidence.value == 1.0
