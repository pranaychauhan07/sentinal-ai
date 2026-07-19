"""Unit tests for core/knowledge/mitre/loader.py."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from core.config import get_settings
from core.knowledge.mitre.exceptions import MalformedMitreDataError
from core.knowledge.mitre.loader import load_bundle, load_bundle_from_path
from core.knowledge.mitre.models import MitreRelationshipType


def _minimal_bundle() -> dict[str, Any]:
    return {
        "type": "bundle",
        "spec_version": "2.1",
        "x_mitre_attack_spec_version": "1.0-test",
        "objects": [
            {
                "type": "x-mitre-tactic",
                "id": "x-mitre-tactic--t1",
                "name": "Credential Access",
                "x_mitre_shortname": "credential-access",
                "description": "Stealing credentials.",
                "external_references": [{"source_name": "mitre-attack", "external_id": "TA0006"}],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--p1",
                "name": "Brute Force",
                "description": "Guessing passwords.",
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}
                ],
                "x_mitre_platforms": ["Windows"],
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1110"}],
            },
            {
                "type": "tool",
                "id": "tool--s1",
                "name": "Mimikatz",
                "description": "Credential dumper.",
                "external_references": [{"source_name": "mitre-attack", "external_id": "S0002"}],
            },
            {
                "type": "intrusion-set",
                "id": "intrusion-set--g1",
                "name": "APT28",
                "description": "A threat group.",
                "external_references": [{"source_name": "mitre-attack", "external_id": "G0007"}],
            },
            {
                "type": "course-of-action",
                "id": "course-of-action--m1",
                "name": "Multi-factor Authentication",
                "description": "Use MFA.",
                "external_references": [{"source_name": "mitre-attack", "external_id": "M1032"}],
            },
            {
                "type": "relationship",
                "id": "relationship--r1",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--g1",
                "target_ref": "attack-pattern--p1",
                "description": "APT28 uses brute force.",
            },
            {
                "type": "relationship",
                "id": "relationship--r2",
                "relationship_type": "mitigates",
                "source_ref": "course-of-action--m1",
                "target_ref": "attack-pattern--p1",
                "description": "MFA mitigates brute force.",
            },
            {
                "type": "identity",
                "id": "identity--unmodeled",
                "name": "The MITRE Corporation",
            },
        ],
    }


@pytest.mark.unit
def test_load_bundle_parses_every_object_type() -> None:
    dataset = load_bundle(_minimal_bundle())
    assert dataset.attack_spec_version == "1.0-test"
    assert len(dataset.tactics) == 1
    assert len(dataset.techniques) == 1
    assert len(dataset.software) == 1
    assert len(dataset.groups) == 1
    assert len(dataset.mitigations) == 1
    assert len(dataset.relationships) == 2


@pytest.mark.unit
def test_load_bundle_resolves_relationship_business_ids() -> None:
    dataset = load_bundle(_minimal_bundle())
    uses = next(
        r for r in dataset.relationships if r.relationship_type is MitreRelationshipType.USES
    )
    assert uses.source_id == "G0007"
    assert uses.target_id == "T1110"
    mitigates = next(
        r for r in dataset.relationships if r.relationship_type is MitreRelationshipType.MITIGATES
    )
    assert mitigates.source_id == "M1032"
    assert mitigates.target_id == "T1110"


@pytest.mark.unit
def test_load_bundle_technique_carries_all_tactic_phases() -> None:
    bundle = _minimal_bundle()
    bundle["objects"][1]["kill_chain_phases"].append(
        {"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"}
    )
    dataset = load_bundle(bundle)
    assert set(dataset.techniques[0].tactic_shortnames) == {"credential-access", "defense-evasion"}


@pytest.mark.unit
def test_load_bundle_skips_object_missing_external_id() -> None:
    bundle = _minimal_bundle()
    bundle["objects"][1]["external_references"] = []
    dataset = load_bundle(bundle)
    assert dataset.techniques == ()


@pytest.mark.unit
def test_load_bundle_skips_relationship_to_unmodeled_object() -> None:
    bundle = _minimal_bundle()
    bundle["objects"].append(
        {
            "type": "relationship",
            "id": "relationship--r3",
            "relationship_type": "uses",
            "source_ref": "intrusion-set--g1",
            "target_ref": "identity--unmodeled",
        }
    )
    dataset = load_bundle(bundle)
    assert len(dataset.relationships) == 2


@pytest.mark.unit
def test_load_bundle_rejects_missing_objects_key() -> None:
    with pytest.raises(MalformedMitreDataError):
        load_bundle({"type": "bundle"})


@pytest.mark.unit
def test_load_bundle_rejects_missing_version_with_no_override() -> None:
    bundle = _minimal_bundle()
    del bundle["x_mitre_attack_spec_version"]
    with pytest.raises(MalformedMitreDataError):
        load_bundle(bundle)


@pytest.mark.unit
def test_load_bundle_accepts_explicit_version_override() -> None:
    bundle = _minimal_bundle()
    del bundle["x_mitre_attack_spec_version"]
    dataset = load_bundle(bundle, attack_spec_version="99.0")
    assert dataset.attack_spec_version == "99.0"


@pytest.mark.unit
def test_load_bundle_from_path_reads_file(tmp_path: Path) -> None:
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(_minimal_bundle()), encoding="utf-8")
    dataset = load_bundle_from_path(bundle_path)
    assert dataset.attack_spec_version == "1.0-test"


@pytest.mark.unit
def test_load_bundle_from_path_rejects_invalid_json(tmp_path: Path) -> None:
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(MalformedMitreDataError):
        load_bundle_from_path(bundle_path)


@pytest.mark.unit
def test_load_bundle_from_path_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(MalformedMitreDataError):
        load_bundle_from_path(tmp_path / "does-not-exist.json")


@pytest.mark.unit
def test_vendored_bundle_loads_and_matches_configured_version() -> None:
    """The actual vendored bundle this repository ships must parse cleanly
    and agree with the default `Settings.mitre_attack_version` — a
    regression guard against the data file and settings default drifting
    apart (constitution §11, "Regression tests")."""
    settings = get_settings()
    dataset = load_bundle_from_path(settings.mitre_attack_data_path)
    assert dataset.attack_spec_version == settings.mitre_attack_version
    assert len(dataset.tactics) == 14
    assert len(dataset.techniques) == 20
    assert len(dataset.software) == 5
    assert len(dataset.groups) == 5
    assert len(dataset.mitigations) == 6
    assert len(dataset.relationships) >= 30
