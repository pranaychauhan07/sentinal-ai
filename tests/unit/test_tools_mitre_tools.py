"""Unit tests for core/tools/mitre_tools.py."""

from __future__ import annotations

import pytest

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
from core.tools.mitre_tools import (
    MitreCaseMappingInput,
    MitreMappingResolutionTool,
    MitreTechniqueMappingInput,
    parent_technique_id,
)

pytestmark = pytest.mark.unit

_VERSION = "1.0-test"


def _dataset() -> MitreDataset:
    """A small, self-contained dataset covering every resolution axis this
    tool exercises: a parent technique, one of its sub-techniques, a tactic,
    a group, software, and a mitigation."""
    tactic = MitreTactic(
        tactic_id="TA0006",
        name="Credential Access",
        shortname="credential-access",
        description="Stealing account names and passwords.",
        attack_spec_version=_VERSION,
    )
    parent = MitreTechnique(
        technique_id="T1110",
        name="Brute Force",
        description="Guessing passwords.",
        tactic_shortnames=("credential-access",),
        attack_spec_version=_VERSION,
    )
    subtechnique = MitreTechnique(
        technique_id="T1110.001",
        name="Password Guessing",
        description="Guessing passwords one at a time.",
        tactic_shortnames=("credential-access",),
        attack_spec_version=_VERSION,
    )
    unlinked = MitreTechnique(
        technique_id="T1078",
        name="Valid Accounts",
        description="Using stolen valid accounts.",
        tactic_shortnames=("credential-access",),
        attack_spec_version=_VERSION,
    )
    software = MitreSoftware(
        software_id="S0002",
        name="Mimikatz",
        description="Credential dumper.",
        is_malware=False,
        attack_spec_version=_VERSION,
    )
    group = MitreGroup(
        group_id="G0007", name="APT28", description="...", attack_spec_version=_VERSION
    )
    mitigation = MitreMitigation(
        mitigation_id="M1032", name="MFA", description="...", attack_spec_version=_VERSION
    )
    relationships = (
        MitreRelationship(
            relationship_type=MitreRelationshipType.USES,
            source_id="G0007",
            target_id="T1110",
            attack_spec_version=_VERSION,
        ),
        MitreRelationship(
            relationship_type=MitreRelationshipType.USES,
            source_id="S0002",
            target_id="T1110",
            attack_spec_version=_VERSION,
        ),
        MitreRelationship(
            relationship_type=MitreRelationshipType.MITIGATES,
            source_id="M1032",
            target_id="T1110",
            attack_spec_version=_VERSION,
        ),
    )
    return MitreDataset(
        attack_spec_version=_VERSION,
        tactics=(tactic,),
        techniques=(parent, subtechnique, unlinked),
        software=(software,),
        groups=(group,),
        mitigations=(mitigation,),
        relationships=relationships,
    )


def _tool() -> MitreMappingResolutionTool:
    return MitreMappingResolutionTool(lookup=MitreLookup(_dataset()))


def test_parent_technique_id_recognizes_subtechnique_shape() -> None:
    assert parent_technique_id("T1110.001") == "T1110"
    assert parent_technique_id("T1110") is None


def test_resolves_tactic_group_software_mitigation_for_a_technique() -> None:
    tool = _tool()
    output = tool(
        MitreCaseMappingInput(
            mappings=[
                MitreTechniqueMappingInput(technique_id="T1110", confidence=0.8, finding_id="f-1")
            ]
        )
    )
    assert output.technique_count == 1
    resolved = output.resolved_techniques[0]
    assert resolved.technique_name == "Brute Force"
    assert resolved.tactic_ids == ("TA0006",)
    assert resolved.group_ids == ("G0007",)
    assert resolved.group_names == ("APT28",)
    assert resolved.software_ids == ("S0002",)
    assert resolved.mitigation_ids == ("M1032",)
    assert resolved.is_subtechnique is False
    assert resolved.parent_technique_id is None
    assert output.distinct_group_count == 1
    assert output.distinct_software_count == 1
    assert output.tactic_coverage == {"TA0006": 1}


def test_subtechnique_resolves_its_parent_id() -> None:
    tool = _tool()
    output = tool(
        MitreCaseMappingInput(
            mappings=[MitreTechniqueMappingInput(technique_id="T1110.001", confidence=0.5)]
        )
    )
    resolved = output.resolved_techniques[0]
    assert resolved.is_subtechnique is True
    assert resolved.parent_technique_id == "T1110"


def test_unknown_technique_id_degrades_to_unresolved_not_an_error() -> None:
    tool = _tool()
    output = tool(
        MitreCaseMappingInput(
            mappings=[MitreTechniqueMappingInput(technique_id="T9999", confidence=0.5)]
        )
    )
    assert output.technique_count == 0
    assert output.unresolved_technique_ids == ("T9999",)


def test_multiple_findings_for_same_technique_use_max_confidence_and_dedup_findings() -> None:
    tool = _tool()
    output = tool(
        MitreCaseMappingInput(
            mappings=[
                MitreTechniqueMappingInput(technique_id="T1110", confidence=0.3, finding_id="f-1"),
                MitreTechniqueMappingInput(technique_id="T1110", confidence=0.9, finding_id="f-2"),
                MitreTechniqueMappingInput(technique_id="T1110", confidence=0.6, finding_id="f-1"),
            ]
        )
    )
    resolved = output.resolved_techniques[0]
    assert resolved.confidence == 0.9
    assert resolved.supporting_finding_ids == ("f-1", "f-2")


def test_top_n_truncates_by_confidence_descending() -> None:
    tool = _tool()
    output = tool(
        MitreCaseMappingInput(
            mappings=[
                MitreTechniqueMappingInput(technique_id="T1110", confidence=0.9),
                MitreTechniqueMappingInput(technique_id="T1078", confidence=0.2),
            ],
            top_n=1,
        )
    )
    assert len(output.top_techniques) == 1
    assert output.top_techniques[0].technique_id == "T1110"


def test_empty_input_returns_zero_summary() -> None:
    tool = _tool()
    output = tool(MitreCaseMappingInput(mappings=[]))
    assert output.technique_count == 0
    assert output.resolved_techniques == ()
    assert output.unresolved_technique_ids == ()
