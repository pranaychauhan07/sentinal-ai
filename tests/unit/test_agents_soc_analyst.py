"""Unit tests for core/agents/soc_analyst_agent.py — agent-level test
invoking the node function directly (constitution §11), independent of
graph orchestration."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from core.agents.contracts import ExecutionStatus
from core.agents.soc_analyst_agent import SocAnalystAgent, default_soc_analyst_tool_registry
from core.graph.state import CaseInvestigationState
from core.parsers.models import (
    ChainOfCustody,
    EvidenceRecord,
    EvidenceType,
    NormalizedEvidence,
    Severity,
)

pytestmark = pytest.mark.unit


def _custody() -> ChainOfCustody:
    return ChainOfCustody(
        ingested_at=datetime.now(UTC),
        ingested_by="tester",
        original_filename="auth.log",
        sha256="a" * 64,
        file_size_bytes=100,
    )


def _evidence(records: list[EvidenceRecord], *, source: str = "auth.log") -> NormalizedEvidence:
    return NormalizedEvidence(
        evidence_type=EvidenceType.SSH_AUTH,
        source=source,
        parser_name="ssh_auth",
        parser_version="1.0.0",
        confidence=1.0,
        records=records,
        chain_of_custody=_custody(),
    )


def _agent() -> SocAnalystAgent:
    return SocAnalystAgent(tool_registry=default_soc_analyst_tool_registry())


def test_no_evidence_is_degraded_not_a_false_clean_bill() -> None:
    agent = _agent()
    state = CaseInvestigationState()
    result = agent(state)
    assert result.agent_outputs[agent.name].status == ExecutionStatus.DEGRADED


def test_analyzes_normal_traffic_as_low_risk() -> None:
    agent = _agent()
    evidence = _evidence(
        [EvidenceRecord(ip_address="10.0.0.1", event_type="login_success", severity=Severity.INFO)]
    )
    state = CaseInvestigationState(evidence=[evidence])
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    assert output.status == ExecutionStatus.SUCCEEDED
    findings = output.output["findings"]
    assert len(findings) == 1
    assert findings[0]["suspected_brute_force"] is False


def test_detects_suspected_brute_force_from_repeated_failures() -> None:
    agent = _agent()
    records = [
        EvidenceRecord(ip_address="10.0.0.9", event_type="login_failed", severity=Severity.MEDIUM)
        for _ in range(5)
    ]
    evidence = _evidence(records)
    state = CaseInvestigationState(evidence=[evidence])
    result_state = agent(state)
    findings = result_state.agent_outputs[agent.name].output["findings"]
    assert findings[0]["suspected_brute_force"] is True
    assert findings[0]["risk_label"] in {"medium", "high", "critical"}


def test_single_failure_does_not_trigger_brute_force() -> None:
    agent = _agent()
    evidence = _evidence(
        [EvidenceRecord(ip_address="10.0.0.9", event_type="login_failed", severity=Severity.LOW)]
    )
    state = CaseInvestigationState(evidence=[evidence])
    result_state = agent(state)
    findings = result_state.agent_outputs[agent.name].output["findings"]
    assert findings[0]["suspected_brute_force"] is False


def test_findings_are_appended_to_state_findings() -> None:
    agent = _agent()
    evidence = _evidence([EvidenceRecord(event_type="ok", severity=Severity.INFO)])
    state = CaseInvestigationState(evidence=[evidence])
    result_state = agent(state)
    assert len(result_state.findings) == 1


def test_confidence_is_always_deterministic() -> None:
    agent = _agent()
    evidence = _evidence([EvidenceRecord(event_type="ok", severity=Severity.INFO)])
    state = CaseInvestigationState(case_id=uuid.uuid4(), evidence=[evidence])
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    assert output.confidence.value == 1.0


def test_non_normalized_evidence_items_are_skipped_not_crashed() -> None:
    agent = _agent()
    state = CaseInvestigationState(evidence=[{"not": "normalized"}])
    result_state = agent(state)
    output = result_state.agent_outputs[agent.name]
    assert output.status == ExecutionStatus.DEGRADED
    assert output.output["skipped_non_evidence_items"] == 1
