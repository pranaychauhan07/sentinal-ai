"""Unit tests for core/findings/dedup.py."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from core.findings.dedup import FindingDeduplicationEngine, merge_findings
from core.findings.models import (
    DedupDecision,
    FindingConfidence,
    FindingPriority,
    FindingRecord,
    FindingSeverity,
    FindingStatus,
    MappingConfidenceFactors,
    MitreMapping,
    TimelineEntry,
)


def _confidence(composite: float = 0.5) -> FindingConfidence:
    return FindingConfidence(
        ioc_quality=composite,
        evidence_quality=composite,
        supporting_indicator_score=composite,
        rule_strength=composite,
        mapping_quality=composite,
        source_reliability=composite,
        historical_evidence=composite,
        composite=composite,
    )


def _mapping(technique_id: str = "T1110") -> MitreMapping:
    return MitreMapping(
        technique_id=technique_id,
        confidence=0.6,
        mapping_source="rule_based",
        attack_spec_version="1.0-test",
        factors=MappingConfidenceFactors(
            rule_strength=0.5,
            ioc_confidence=0.6,
            evidence_quality=0.6,
            supporting_indicator_count=1,
        ),
    )


def _finding(
    *,
    case_id: uuid.UUID,
    ioc_refs: tuple[uuid.UUID, ...] = (),
    evidence_refs: tuple[uuid.UUID, ...] = (),
    technique_id: str = "T1110",
    affected_assets: tuple[str, ...] = (),
    status: FindingStatus = FindingStatus.OPEN,
    occurred_at: datetime | None = None,
) -> FindingRecord:
    occurred_at = occurred_at or datetime.now(UTC)
    return FindingRecord(
        case_id=case_id,
        title="test finding",
        description="test",
        severity=FindingSeverity.MEDIUM,
        confidence=_confidence(),
        status=status,
        priority=FindingPriority.P3_MEDIUM,
        evidence_refs=evidence_refs,
        ioc_refs=ioc_refs,
        mitre_mappings=(_mapping(technique_id),),
        timeline=(TimelineEntry(occurred_at=occurred_at, description="seen"),),
        affected_assets=affected_assets,
        risk_score=50.0,
    )


@pytest.mark.unit
def test_no_existing_findings_yields_new() -> None:
    engine = FindingDeduplicationEngine()
    result = engine.evaluate(
        candidate_ioc_ids=(uuid.uuid4(),),
        candidate_evidence_ids=(),
        candidate_mappings=[_mapping()],
        candidate_affected_assets=(),
        candidate_first_seen=datetime.now(UTC),
        candidate_last_seen=datetime.now(UTC),
        existing_findings=[],
        similarity_threshold=0.6,
    )
    assert result.decision is DedupDecision.NEW
    assert result.matched_finding_id is None


@pytest.mark.unit
def test_identical_content_merges() -> None:
    case_id = uuid.uuid4()
    shared_ioc = uuid.uuid4()
    now = datetime.now(UTC)
    existing = _finding(case_id=case_id, ioc_refs=(shared_ioc,), occurred_at=now)

    engine = FindingDeduplicationEngine()
    result = engine.evaluate(
        candidate_ioc_ids=(shared_ioc,),
        candidate_evidence_ids=(),
        candidate_mappings=[_mapping()],
        candidate_affected_assets=(),
        candidate_first_seen=now,
        candidate_last_seen=now,
        existing_findings=[existing],
        similarity_threshold=0.6,
    )
    assert result.decision is DedupDecision.MERGE
    assert result.matched_finding_id == existing.finding_id
    assert result.matched_dimensions["hash"] == 1.0


@pytest.mark.unit
def test_non_overlapping_finding_is_prefiltered_out() -> None:
    case_id = uuid.uuid4()
    unrelated = _finding(
        case_id=case_id,
        ioc_refs=(uuid.uuid4(),),
        technique_id="T1078",
        occurred_at=datetime.now(UTC) - timedelta(days=30),
    )
    engine = FindingDeduplicationEngine()
    result = engine.evaluate(
        candidate_ioc_ids=(uuid.uuid4(),),
        candidate_evidence_ids=(),
        candidate_mappings=[_mapping("T1486")],
        candidate_affected_assets=(),
        candidate_first_seen=datetime.now(UTC),
        candidate_last_seen=datetime.now(UTC),
        existing_findings=[unrelated],
        similarity_threshold=0.6,
    )
    assert result.decision is DedupDecision.NEW
    assert result.matched_finding_id is None


@pytest.mark.unit
def test_time_window_score_decays_outside_window() -> None:
    case_id = uuid.uuid4()
    shared_asset = "host-01"
    old_finding = _finding(
        case_id=case_id,
        affected_assets=(shared_asset,),
        occurred_at=datetime.now(UTC) - timedelta(hours=5),
    )
    engine = FindingDeduplicationEngine(time_window_minutes=60)
    result = engine.evaluate(
        candidate_ioc_ids=(),
        candidate_evidence_ids=(),
        candidate_mappings=[_mapping()],
        candidate_affected_assets=(shared_asset,),
        candidate_first_seen=datetime.now(UTC),
        candidate_last_seen=datetime.now(UTC),
        existing_findings=[old_finding],
        similarity_threshold=0.6,
    )
    assert result.matched_dimensions["time_window"] == 0.0


@pytest.mark.unit
def test_merge_findings_unions_evidence_and_iocs() -> None:
    case_id = uuid.uuid4()
    existing = _finding(case_id=case_id, ioc_refs=(uuid.uuid4(),), evidence_refs=(uuid.uuid4(),))
    incoming = _finding(case_id=case_id, ioc_refs=(uuid.uuid4(),), evidence_refs=(uuid.uuid4(),))
    merged = merge_findings(existing, incoming)
    assert set(merged.ioc_refs) == set(existing.ioc_refs) | set(incoming.ioc_refs)
    assert set(merged.evidence_refs) == set(existing.evidence_refs) | set(incoming.evidence_refs)


@pytest.mark.unit
def test_merge_findings_reopens_closed_finding() -> None:
    case_id = uuid.uuid4()
    closed = _finding(case_id=case_id, status=FindingStatus.CLOSED)
    incoming = _finding(case_id=case_id)
    merged = merge_findings(closed, incoming)
    assert merged.status is FindingStatus.OPEN


@pytest.mark.unit
def test_merge_findings_keeps_higher_risk_score() -> None:
    case_id = uuid.uuid4()
    existing = _finding(case_id=case_id).model_copy(update={"risk_score": 30.0})
    incoming = _finding(case_id=case_id).model_copy(update={"risk_score": 80.0})
    merged = merge_findings(existing, incoming)
    assert merged.risk_score == 80.0
