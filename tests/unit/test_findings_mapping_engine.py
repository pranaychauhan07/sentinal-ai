"""Unit tests for core/findings/mapping_engine.py."""

from __future__ import annotations

import pytest
from tests.unit._finding_test_helpers import VERSION, make_dataset, make_scored_ioc

from core.findings.exceptions import InvalidMappingRuleError
from core.findings.mapping_engine import MitreMappingEngine
from core.findings.mapping_rules import MAPPING_RULES
from core.knowledge.mitre.lookup import MitreLookup
from core.knowledge.mitre.models import MitreDataset, MitreTactic, MitreTechnique
from core.threat_intel.models import IOCType, ThreatSeverity

_TEST_TECHNIQUE_IDS = {"T1110", "T1078", "T1486"}
_TEST_RULES = tuple(rule for rule in MAPPING_RULES if rule.technique_id in _TEST_TECHNIQUE_IDS)


def _full_dataset() -> MitreDataset:
    """A minimal dataset covering every technique_id `MAPPING_RULES`
    references — needed to exercise the real, full rule table (not the
    filtered `_TEST_RULES` subset) without depending on the vendored
    MITRE bundle."""
    tactic = MitreTactic(
        tactic_id="TA0000",
        name="Test Tactic",
        shortname="test-tactic",
        description="Placeholder tactic for unit tests.",
        attack_spec_version=VERSION,
    )
    techniques = tuple(
        MitreTechnique(
            technique_id=technique_id,
            name=technique_id,
            description="Placeholder technique for unit tests.",
            tactic_shortnames=("test-tactic",),
            attack_spec_version=VERSION,
        )
        for technique_id in dict.fromkeys(rule.technique_id for rule in MAPPING_RULES)
    )
    return MitreDataset(
        attack_spec_version=VERSION,
        tactics=(tactic,),
        techniques=techniques,
        software=(),
        groups=(),
        mitigations=(),
        relationships=(),
    )


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
def test_mapping_carries_rule_id_and_rationale() -> None:
    engine = _engine()
    ioc = make_scored_ioc(ioc_type=IOCType.USERNAME, value="admin")
    mapping = next(m for m in engine([ioc]) if m.technique_id == "T1110")
    assert mapping.rule_id == "R-T1110-brute-force"
    assert "admin" in mapping.rationale
    assert mapping.rationale  # non-empty, human-readable


@pytest.mark.unit
def test_require_co_occurrence_gates_a_rule_entirely_when_absent() -> None:
    """A rule with `require_co_occurrence=True` must not fire at all
    without its co-occurrence type present — distinct from the default
    boost-only behavior other rules use."""
    from core.findings.mapping_rules import MappingRule

    gated_rule = MappingRule(
        rule_id="R-test-gated",
        technique_id="T1078",
        ioc_types=(IOCType.FILE_NAME,),
        base_confidence=0.9,
        co_occurrence_ioc_types=(IOCType.EMAIL,),
        require_co_occurrence=True,
    )
    engine = MitreMappingEngine(lookup=MitreLookup(make_dataset()), rules=(gated_rule,))

    without_email = engine([make_scored_ioc(ioc_type=IOCType.FILE_NAME, value="payload.exe")])
    assert without_email == []

    with_email = engine(
        [
            make_scored_ioc(ioc_type=IOCType.FILE_NAME, value="payload.exe"),
            make_scored_ioc(ioc_type=IOCType.EMAIL, value="a@b.example"),
        ]
    )
    assert any(m.technique_id == "T1078" for m in with_email)


@pytest.mark.unit
def test_real_ssh_auth_log_shaped_iocs_do_not_map_to_tightened_techniques() -> None:
    """Regression test for the exact false-positive pattern a real
    investigation report found: a plain SSH auth log's IOCs (many
    ephemeral ports, a source IP, several usernames, the log's own source
    hostname — no tags, no email) must map only to genuinely-supported
    techniques (Brute Force / Valid Accounts / Remote Services), never to
    Network Service Discovery, System Info Discovery, Masquerading,
    Proxy, Remote System Discovery, or User Execution."""
    from core.findings.mapping_rules import MAPPING_RULES

    engine = MitreMappingEngine(lookup=MitreLookup(_full_dataset()), rules=MAPPING_RULES)
    iocs = [
        make_scored_ioc(ioc_type=IOCType.USERNAME, value="admin"),
        make_scored_ioc(ioc_type=IOCType.USERNAME, value="root"),
        make_scored_ioc(ioc_type=IOCType.IPV4, value="203.0.113.44"),
        make_scored_ioc(ioc_type=IOCType.PORT, value="51422"),
        make_scored_ioc(ioc_type=IOCType.PORT, value="51430"),
        make_scored_ioc(ioc_type=IOCType.HOSTNAME, value="web-prod-01"),
    ]
    technique_ids = {m.technique_id for m in engine(iocs)}
    assert technique_ids & {"T1110", "T1078", "T1021"}
    assert not technique_ids & {"T1046", "T1082", "T1036", "T1090", "T1018", "T1204"}


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
