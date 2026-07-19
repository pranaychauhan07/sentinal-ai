"""Unit tests for core/findings/mapping_engine.py."""

from __future__ import annotations

import pytest
from tests.unit._finding_test_helpers import make_dataset, make_scored_ioc

from core.findings.exceptions import InvalidMappingRuleError
from core.findings.mapping_engine import MitreMappingEngine
from core.findings.mapping_rules import MAPPING_RULES
from core.knowledge.mitre.lookup import MitreLookup
from core.threat_intel.models import IOCType, ThreatSeverity

_TEST_TECHNIQUE_IDS = {"T1110", "T1078", "T1486"}
_TEST_RULES = tuple(rule for rule in MAPPING_RULES if rule.technique_id in _TEST_TECHNIQUE_IDS)


def _engine(min_confidence: float = 0.0) -> MitreMappingEngine:
    return MitreMappingEngine(
        lookup=MitreLookup(make_dataset()), rules=_TEST_RULES, min_confidence=min_confidence
    )


@pytest.mark.unit
def test_rejects_rule_referencing_unknown_technique() -> None:
    from core.findings.mapping_rules import MappingRule

    bad_rule = MappingRule(
        rule_id="bad", technique_id="T9999", ioc_types=(IOCType.USERNAME,), base_confidence=0.5
    )
    with pytest.raises(InvalidMappingRuleError):
        MitreMappingEngine(lookup=MitreLookup(make_dataset()), rules=(bad_rule,))


@pytest.mark.unit
def test_username_ioc_maps_to_multiple_techniques() -> None:
    """one-IOC-to-many-techniques: a USERNAME IOC matches both the Brute
    Force and Valid Accounts rules."""
    engine = _engine()
    ioc = make_scored_ioc(ioc_type=IOCType.USERNAME, value="admin")
    mappings = engine([ioc])
    technique_ids = {m.technique_id for m in mappings}
    assert technique_ids == {"T1110", "T1078"}


@pytest.mark.unit
def test_co_occurrence_boosts_confidence() -> None:
    """many-IOCs-to-one-technique: a USERNAME + IPV4 pair scores higher on
    Brute Force than the username alone."""
    engine = _engine()
    username_only = engine([make_scored_ioc(ioc_type=IOCType.USERNAME, value="admin")])
    brute_force_only = next(m for m in username_only if m.technique_id == "T1110")

    with_ip = engine(
        [
            make_scored_ioc(ioc_type=IOCType.USERNAME, value="admin"),
            make_scored_ioc(ioc_type=IOCType.IPV4, value="203.0.113.5"),
        ]
    )
    brute_force_with_ip = next(m for m in with_ip if m.technique_id == "T1110")

    assert brute_force_with_ip.confidence > brute_force_only.confidence


@pytest.mark.unit
def test_tag_gated_rule_requires_matching_tag() -> None:
    engine = _engine()
    untagged = make_scored_ioc(ioc_type=IOCType.FILE_NAME, value="notes.txt", tags=())
    assert engine([untagged]) == []

    tagged = make_scored_ioc(ioc_type=IOCType.FILE_NAME, value="locker.exe", tags=("ransomware",))
    mappings = engine([tagged])
    assert any(m.technique_id == "T1486" for m in mappings)


@pytest.mark.unit
def test_mapping_includes_resolved_tactic_ids() -> None:
    engine = _engine()
    ioc = make_scored_ioc(ioc_type=IOCType.USERNAME, value="admin")
    mapping = next(m for m in engine([ioc]) if m.technique_id == "T1110")
    assert mapping.tactic_ids == ("TA0006",)


@pytest.mark.unit
def test_min_confidence_filters_low_confidence_mappings() -> None:
    engine = _engine(min_confidence=0.99)
    ioc = make_scored_ioc(ioc_type=IOCType.USERNAME, value="admin", confidence=0.2)
    assert engine([ioc]) == []


@pytest.mark.unit
def test_no_matching_rule_returns_empty() -> None:
    engine = _engine()
    ioc = make_scored_ioc(ioc_type=IOCType.MUTEX, value="Global\\weird-mutex")
    assert engine([ioc]) == []


@pytest.mark.unit
def test_multiple_iocs_aggregate_into_one_mapping_per_technique() -> None:
    engine = _engine()
    iocs = [
        make_scored_ioc(ioc_type=IOCType.USERNAME, value="admin"),
        make_scored_ioc(ioc_type=IOCType.USERNAME, value="root"),
    ]
    mappings = engine(iocs)
    brute_force = next(m for m in mappings if m.technique_id == "T1110")
    assert len(brute_force.supporting_ioc_ids) == 2
    assert brute_force.factors.supporting_indicator_count == 2


@pytest.mark.unit
def test_severity_of_iocs_does_not_affect_mapping_confidence_directly() -> None:
    """Mapping confidence is a function of rule strength/IOC confidence/
    evidence quality, not the IOC's own severity — severity feeds the
    Finding-level severity assignment instead (core.findings.severity)."""
    engine = _engine()
    low_sev = engine([make_scored_ioc(ioc_type=IOCType.USERNAME, severity=ThreatSeverity.INFO)])
    high_sev = engine(
        [make_scored_ioc(ioc_type=IOCType.USERNAME, severity=ThreatSeverity.CRITICAL)]
    )
    conf_low = next(m for m in low_sev if m.technique_id == "T1110").confidence
    conf_high = next(m for m in high_sev if m.technique_id == "T1110").confidence
    assert conf_low == conf_high
