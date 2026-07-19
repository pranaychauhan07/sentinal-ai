"""Unit tests for core/findings/evidence_aggregation.py."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from tests.unit._finding_test_helpers import make_scored_ioc

from core.findings.evidence_aggregation import EvidenceAggregator
from core.threat_intel.models import IOCType


@pytest.mark.unit
def test_aggregate_requires_at_least_one_ioc() -> None:
    with pytest.raises(ValueError, match="at least one"):
        EvidenceAggregator().aggregate([])


@pytest.mark.unit
def test_aggregate_collects_ioc_and_evidence_ids() -> None:
    evidence_id = uuid.uuid4()
    ioc = make_scored_ioc(evidence_id=evidence_id)
    bundle = EvidenceAggregator().aggregate([ioc])
    assert bundle.ioc_ids == (ioc.record.ioc_id,)
    assert bundle.evidence_ids == (evidence_id,)


@pytest.mark.unit
def test_aggregate_deduplicates_evidence_ids() -> None:
    evidence_id = uuid.uuid4()
    iocs = [
        make_scored_ioc(evidence_id=evidence_id, value="1.1.1.1"),
        make_scored_ioc(evidence_id=evidence_id, value="2.2.2.2"),
    ]
    bundle = EvidenceAggregator().aggregate(iocs)
    assert bundle.evidence_ids == (evidence_id,)


@pytest.mark.unit
def test_aggregate_extracts_asset_iocs_only() -> None:
    iocs = [
        make_scored_ioc(ioc_type=IOCType.IPV4, value="10.0.0.5"),
        make_scored_ioc(ioc_type=IOCType.HOSTNAME, value="workstation-01"),
        make_scored_ioc(ioc_type=IOCType.USERNAME, value="admin"),
    ]
    bundle = EvidenceAggregator().aggregate(iocs)
    assert set(bundle.affected_assets) == {"10.0.0.5", "workstation-01"}


@pytest.mark.unit
def test_aggregate_builds_sorted_timeline() -> None:
    now = datetime.now(UTC)
    earlier = make_scored_ioc(value="1.1.1.1", first_seen=now - timedelta(hours=1))
    later = make_scored_ioc(value="2.2.2.2", first_seen=now)
    bundle = EvidenceAggregator().aggregate([later, earlier])
    assert [entry.occurred_at for entry in bundle.timeline] == sorted(
        entry.occurred_at for entry in bundle.timeline
    )
    assert bundle.timeline[0].occurred_at == earlier.attribution.first_seen


@pytest.mark.unit
def test_aggregate_first_and_last_seen_span_all_iocs() -> None:
    now = datetime.now(UTC)
    earlier = make_scored_ioc(value="1.1.1.1", first_seen=now - timedelta(hours=2))
    later = make_scored_ioc(value="2.2.2.2", first_seen=now)
    bundle = EvidenceAggregator().aggregate([earlier, later])
    assert bundle.first_seen == earlier.attribution.first_seen
    assert bundle.last_seen == later.attribution.last_seen
