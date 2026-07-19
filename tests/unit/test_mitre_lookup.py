"""Unit tests for core/knowledge/mitre/lookup.py."""

from __future__ import annotations

import pytest

from core.knowledge.mitre.exceptions import UnknownTechniqueError
from core.knowledge.mitre.lookup import MitreLookup
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

VERSION = "1.0-test"


def _dataset() -> MitreDataset:
    tactic = MitreTactic(
        tactic_id="TA0006",
        name="Credential Access",
        shortname="credential-access",
        description="...",
        attack_spec_version=VERSION,
    )
    technique = MitreTechnique(
        technique_id="T1110",
        name="Brute Force",
        description="...",
        tactic_shortnames=("credential-access",),
        attack_spec_version=VERSION,
    )
    software = MitreSoftware(
        software_id="S0002",
        name="Mimikatz",
        description="...",
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
            relationship_type=MitreRelationshipType.USES,
            source_id="S0002",
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
        tactics=(tactic,),
        techniques=(technique,),
        software=(software,),
        groups=(group,),
        mitigations=(mitigation,),
        relationships=relationships,
    )


@pytest.mark.unit
def test_technique_by_id_returns_technique() -> None:
    lookup = MitreLookup(_dataset())
    assert lookup.technique_by_id("T1110").name == "Brute Force"


@pytest.mark.unit
def test_technique_by_id_raises_for_unknown_id() -> None:
    lookup = MitreLookup(_dataset())
    with pytest.raises(UnknownTechniqueError):
        lookup.technique_by_id("T9999")


@pytest.mark.unit
def test_has_technique() -> None:
    lookup = MitreLookup(_dataset())
    assert lookup.has_technique("T1110")
    assert not lookup.has_technique("T9999")


@pytest.mark.unit
def test_tactics_for_technique() -> None:
    lookup = MitreLookup(_dataset())
    tactics = lookup.tactics_for_technique("T1110")
    assert [t.tactic_id for t in tactics] == ["TA0006"]


@pytest.mark.unit
def test_mitigations_for_technique() -> None:
    lookup = MitreLookup(_dataset())
    mitigations = lookup.mitigations_for_technique("T1110")
    assert [m.mitigation_id for m in mitigations] == ["M1032"]


@pytest.mark.unit
def test_mitigations_for_technique_empty_when_none() -> None:
    lookup = MitreLookup(_dataset())
    assert lookup.mitigations_for_technique("T1110") != ()
    dataset_without_rel = _dataset().model_copy(update={"relationships": ()})
    lookup_empty = MitreLookup(dataset_without_rel)
    assert lookup_empty.mitigations_for_technique("T1110") == ()


@pytest.mark.unit
def test_groups_using_technique() -> None:
    lookup = MitreLookup(_dataset())
    groups = lookup.groups_using_technique("T1110")
    assert [g.group_id for g in groups] == ["G0007"]


@pytest.mark.unit
def test_software_using_technique() -> None:
    lookup = MitreLookup(_dataset())
    software = lookup.software_using_technique("T1110")
    assert [s.software_id for s in software] == ["S0002"]


@pytest.mark.unit
def test_all_technique_ids() -> None:
    lookup = MitreLookup(_dataset())
    assert lookup.all_technique_ids() == ("T1110",)
