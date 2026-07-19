"""Shared test-only helpers for building `ScoredIOC` fixtures across
`test_findings_*.py` and `test_mitre_*.py` — not collected as tests itself
(no `test_` prefix)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from core.knowledge.mitre.models import (
    MitreDataset,
    MitreGroup,
    MitreMitigation,
    MitreRelationship,
    MitreRelationshipType,
    MitreSoftware,
    MitreTactic,
    MitreTechnique,
)
from core.threat_intel.models import (
    AttributionRecord,
    IOCClassification,
    IOCRecord,
    IOCType,
    RuleMatchResult,
    ScoredIOC,
    ThreatCategory,
    ThreatScore,
    ThreatSeverity,
)

VERSION = "1.0-test"


def make_scored_ioc(
    *,
    ioc_type: IOCType = IOCType.IPV4,
    value: str = "203.0.113.10",
    severity: ThreatSeverity = ThreatSeverity.MEDIUM,
    confidence: float = 0.8,
    evidence_quality: float = 0.7,
    tags: tuple[str, ...] = (),
    evidence_id: uuid.UUID | None = None,
    first_seen: datetime | None = None,
    last_seen: datetime | None = None,
    rule_matches: tuple[RuleMatchResult, ...] = (),
    classification: ThreatCategory = ThreatCategory.SUSPICIOUS,
) -> ScoredIOC:
    first_seen = first_seen or datetime.now(UTC)
    last_seen = last_seen or first_seen
    record = IOCRecord(
        ioc_type=ioc_type,
        value=value,
        raw_value=value,
        source="test-source",
        severity=severity,
        confidence=confidence,
        tags=tags,
        evidence_id=evidence_id,
        first_seen=first_seen,
    )
    score = ThreatScore(
        confidence=confidence,
        severity_weight=0.5,
        impact=0.5,
        likelihood=0.5,
        evidence_quality=evidence_quality,
        source_reliability=0.5,
        rule_match_score=0.0,
        composite_score=50.0,
    )
    return ScoredIOC(
        record=record,
        rule_matches=rule_matches,
        score=score,
        classification=IOCClassification(category=classification, reason="test fixture"),
        attribution=AttributionRecord(
            ioc_id=record.ioc_id,
            evidence_id=evidence_id,
            source="test-source",
            first_seen=first_seen,
            last_seen=last_seen,
        ),
    )


def make_dataset() -> MitreDataset:
    """A small, self-contained MITRE dataset covering enough of the real
    vendored bundle's shape (one technique per tactic used by
    `core.findings.mapping_rules`) for mapping-engine tests without
    depending on the full vendored file."""
    tactic = MitreTactic(
        tactic_id="TA0006",
        name="Credential Access",
        shortname="credential-access",
        description="Stealing account names and passwords.",
        attack_spec_version=VERSION,
    )
    impact_tactic = MitreTactic(
        tactic_id="TA0040",
        name="Impact",
        shortname="impact",
        description="Manipulate, interrupt, or destroy systems and data.",
        attack_spec_version=VERSION,
    )
    technique_brute_force = MitreTechnique(
        technique_id="T1110",
        name="Brute Force",
        description="Guessing passwords.",
        tactic_shortnames=("credential-access",),
        attack_spec_version=VERSION,
    )
    technique_valid_accounts = MitreTechnique(
        technique_id="T1078",
        name="Valid Accounts",
        description="Using stolen valid accounts.",
        tactic_shortnames=("credential-access",),
        attack_spec_version=VERSION,
    )
    technique_impact = MitreTechnique(
        technique_id="T1486",
        name="Data Encrypted for Impact",
        description="Ransomware-style encryption.",
        tactic_shortnames=("impact",),
        attack_spec_version=VERSION,
    )
    software = MitreSoftware(
        software_id="S0002",
        name="Mimikatz",
        description="Credential dumper.",
        is_malware=False,
        attack_spec_version=VERSION,
    )
    group = MitreGroup(
        group_id="G0007", name="APT28", description="...", attack_spec_version=VERSION
    )
    mitigation = MitreMitigation(
        mitigation_id="M1032", name="MFA", description="...", attack_spec_version=VERSION
    )
    relationships = (
        MitreRelationship(
            relationship_type=MitreRelationshipType.USES,
            source_id="G0007",
            target_id="T1110",
            attack_spec_version=VERSION,
        ),
        MitreRelationship(
            relationship_type=MitreRelationshipType.MITIGATES,
            source_id="M1032",
            target_id="T1110",
            attack_spec_version=VERSION,
        ),
    )
    return MitreDataset(
        attack_spec_version=VERSION,
        tactics=(tactic, impact_tactic),
        techniques=(technique_brute_force, technique_valid_accounts, technique_impact),
        software=(software,),
        groups=(group,),
        mitigations=(mitigation,),
        relationships=relationships,
    )
