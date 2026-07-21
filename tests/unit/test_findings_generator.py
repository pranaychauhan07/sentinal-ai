"""Unit tests for core/findings/finding_generator.py."""

from __future__ import annotations

import uuid

import pytest
from tests.unit._finding_test_helpers import make_dataset, make_scored_ioc

from core.findings.finding_generator import FindingGenerationEngine
from core.findings.mapping_engine import MitreMappingEngine
from core.findings.mapping_rules import MAPPING_RULES
from core.findings.models import FindingStatus
from core.knowledge.mitre.lookup import MitreLookup
from core.threat_intel.models import IOCType

_TEST_RULES = tuple(r for r in MAPPING_RULES if r.technique_id in {"T1110", "T1078"})


def _generation_engine() -> FindingGenerationEngine:
    lookup = MitreLookup(make_dataset())
    mapping_engine = MitreMappingEngine(lookup=lookup, rules=_TEST_RULES)
    return FindingGenerationEngine(mapping_engine=mapping_engine, lookup=lookup)


@pytest.mark.unit
def test_unmapped_iocs_produce_no_findings() -> None:
    engine = _generation_engine()
    iocs = [make_scored_ioc(ioc_type=IOCType.MUTEX, value="Global\\weird")]
    findings = engine.generate(uuid.uuid4(), iocs)
    assert findings == []


@pytest.mark.unit
def test_mapped_iocs_produce_one_finding_per_technique() -> None:
    engine = _generation_engine()
    case_id = uuid.uuid4()
    findings = engine.generate(case_id, [make_scored_ioc(ioc_type=IOCType.USERNAME, value="admin")])
    technique_ids = {f.mitre_mappings[0].technique_id for f in findings}
    assert technique_ids == {"T1110", "T1078"}
    assert all(f.case_id == case_id for f in findings)
    assert all(f.status is FindingStatus.OPEN for f in findings)


@pytest.mark.unit
def test_finding_title_includes_technique_name_and_id() -> None:
    engine = _generation_engine()
    findings = engine.generate(uuid.uuid4(), [make_scored_ioc(ioc_type=IOCType.USERNAME)])
    brute_force = next(f for f in findings if f.mitre_mappings[0].technique_id == "T1110")
    assert "Brute Force" in brute_force.title
    assert "T1110" in brute_force.title


@pytest.mark.unit
def test_finding_carries_evidence_and_ioc_refs() -> None:
    engine = _generation_engine()
    ioc = make_scored_ioc(ioc_type=IOCType.USERNAME)
    findings = engine.generate(uuid.uuid4(), [ioc])
    assert findings
    assert ioc.record.ioc_id in findings[0].ioc_refs


@pytest.mark.unit
def test_finding_has_positive_risk_score() -> None:
    engine = _generation_engine()
    findings = engine.generate(uuid.uuid4(), [make_scored_ioc(ioc_type=IOCType.USERNAME)])
    assert all(f.risk_score > 0.0 for f in findings)


@pytest.mark.unit
def test_finding_title_is_evidence_specific_not_generic() -> None:
    """Detection-quality requirement: a Finding's title must name the
    actual supporting evidence, not just restate the technique name/ID
    (the previous, overly generic '{name} ({id}) detected' shape a real
    investigation report flagged as unsupportive)."""
    engine = _generation_engine()
    findings = engine.generate(
        uuid.uuid4(), [make_scored_ioc(ioc_type=IOCType.USERNAME, value="admin")]
    )
    brute_force = next(f for f in findings if f.mitre_mappings[0].technique_id == "T1110")
    assert "admin" in brute_force.title
    assert "detected" not in brute_force.title.lower()


@pytest.mark.unit
def test_finding_explanation_is_populated() -> None:
    engine = _generation_engine()
    findings = engine.generate(
        uuid.uuid4(), [make_scored_ioc(ioc_type=IOCType.USERNAME, value="admin")]
    )
    for finding in findings:
        assert finding.explanation is not None
        assert "admin" in finding.explanation.evidence_summary
        assert finding.explanation.severity_rationale


@pytest.mark.unit
def test_finding_description_names_the_triggering_rule() -> None:
    engine = _generation_engine()
    findings = engine.generate(
        uuid.uuid4(), [make_scored_ioc(ioc_type=IOCType.USERNAME, value="admin")]
    )
    brute_force = next(f for f in findings if f.mitre_mappings[0].technique_id == "T1110")
    assert "R-T1110-brute-force" in brute_force.description


@pytest.mark.unit
def test_evidence_summary_truncates_many_supporting_iocs() -> None:
    engine = _generation_engine()
    iocs = [make_scored_ioc(ioc_type=IOCType.USERNAME, value=f"user{i}") for i in range(6)]
    findings = engine.generate(uuid.uuid4(), iocs)
    brute_force = next(f for f in findings if f.mitre_mappings[0].technique_id == "T1110")
    assert "and 3 more" in brute_force.explanation.evidence_summary
