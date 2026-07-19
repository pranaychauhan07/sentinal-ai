"""STIX 2.1 bundle loader — the one place ATT&CK STIX parsing happens
(constitution §1.9, "never duplicated across files"). Consumed by
`core.knowledge.mitre.source.MitreAttackSource` (in-memory, at process
startup) and `scripts/mitre/import_attack_bundle.py` (DB seeding) alike, so
adding a new ATT&CK release never requires an application-code change
(docs/adr/0013-finding-mitre-intelligence-engine-shape.md point 4) — only a
new vendored file under `data/mitre/raw/`.

Reads a local file only. Never performs a network request — the offline
requirement is structural here, not a convention (constitution §10, "safe
defaults").
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.knowledge.mitre.exceptions import MalformedMitreDataError
from core.knowledge.mitre.models import (
    MitreDataset,
    MitreGroup,
    MitreMitigation,
    MitreObjectType,
    MitreRelationship,
    MitreRelationshipType,
    MitreSoftware,
    MitreTactic,
    MitreTechnique,
)
from core.logging import get_logger

_logger = get_logger(__name__)

_MITRE_SOURCE_NAME = "mitre-attack"


def _external_id(obj: dict[str, Any]) -> str | None:
    for reference in obj.get("external_references", []):
        if reference.get("source_name") == _MITRE_SOURCE_NAME and reference.get("external_id"):
            return str(reference["external_id"])
    return None


def load_bundle_from_path(path: Path, *, attack_spec_version: str | None = None) -> MitreDataset:
    """Read and parse a vendored STIX bundle file. Raises
    :class:`MalformedMitreDataError` if the file is not valid JSON — every
    other malformed *individual object* degrades to a skipped, logged
    entry rather than aborting the whole load (constitution §1.7)."""
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise MalformedMitreDataError(
            f"Could not read MITRE bundle file: {path}", details={"path": str(path)}
        ) from exc
    try:
        bundle = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise MalformedMitreDataError(
            f"MITRE bundle file is not valid JSON: {path}", details={"path": str(path)}
        ) from exc
    return load_bundle(bundle, attack_spec_version=attack_spec_version)


def load_bundle(bundle: dict[str, Any], *, attack_spec_version: str | None = None) -> MitreDataset:
    """Parse an in-memory STIX 2.1 bundle dict into a typed
    :class:`MitreDataset`. Objects of a type this engine doesn't model
    (identities, marking-definitions, etc.) are silently ignored — only
    known-but-malformed objects (e.g. a technique with no ATT&CK external
    ID) are logged as skipped, never raised as a hard failure."""
    if not isinstance(bundle, dict) or "objects" not in bundle:
        raise MalformedMitreDataError(
            "MITRE bundle is not a STIX bundle (missing top-level 'objects').",
        )

    version = attack_spec_version or bundle.get("x_mitre_attack_spec_version")
    if not version:
        raise MalformedMitreDataError(
            "MITRE bundle has no 'x_mitre_attack_spec_version' and no "
            "explicit attack_spec_version override was provided."
        )
    version = str(version)

    objects: list[dict[str, Any]] = bundle["objects"]
    stix_id_to_business_id: dict[str, str] = {}

    tactics = _parse_tactics(objects, version, stix_id_to_business_id)
    techniques = _parse_techniques(objects, version, stix_id_to_business_id)
    software = _parse_software(objects, version, stix_id_to_business_id)
    groups = _parse_groups(objects, version, stix_id_to_business_id)
    mitigations = _parse_mitigations(objects, version, stix_id_to_business_id)
    relationships = _parse_relationships(objects, version, stix_id_to_business_id)

    return MitreDataset(
        attack_spec_version=version,
        tactics=tuple(tactics),
        techniques=tuple(techniques),
        software=tuple(software),
        groups=tuple(groups),
        mitigations=tuple(mitigations),
        relationships=tuple(relationships),
    )


def _parse_tactics(
    objects: list[dict[str, Any]], version: str, id_map: dict[str, str]
) -> list[MitreTactic]:
    parsed: list[MitreTactic] = []
    for obj in objects:
        if obj.get("type") != MitreObjectType.TACTIC.value:
            continue
        tactic_id = _external_id(obj)
        if not tactic_id or not obj.get("x_mitre_shortname"):
            _logger.warning("mitre_object_skipped", reason="missing tactic id/shortname")
            continue
        id_map[obj["id"]] = tactic_id
        parsed.append(
            MitreTactic(
                tactic_id=tactic_id,
                name=obj.get("name", ""),
                shortname=obj["x_mitre_shortname"],
                description=obj.get("description", ""),
                attack_spec_version=version,
            )
        )
    return parsed


def _parse_techniques(
    objects: list[dict[str, Any]], version: str, id_map: dict[str, str]
) -> list[MitreTechnique]:
    parsed: list[MitreTechnique] = []
    for obj in objects:
        if obj.get("type") != MitreObjectType.TECHNIQUE.value:
            continue
        technique_id = _external_id(obj)
        if not technique_id:
            _logger.warning("mitre_object_skipped", reason="missing technique external id")
            continue
        id_map[obj["id"]] = technique_id
        phases = tuple(
            phase["phase_name"]
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack" and phase.get("phase_name")
        )
        parsed.append(
            MitreTechnique(
                technique_id=technique_id,
                name=obj.get("name", ""),
                description=obj.get("description", ""),
                tactic_shortnames=phases,
                platforms=tuple(obj.get("x_mitre_platforms", [])),
                attack_spec_version=version,
            )
        )
    return parsed


def _parse_software(
    objects: list[dict[str, Any]], version: str, id_map: dict[str, str]
) -> list[MitreSoftware]:
    parsed: list[MitreSoftware] = []
    software_types = {MitreObjectType.SOFTWARE_TOOL.value, MitreObjectType.SOFTWARE_MALWARE.value}
    for obj in objects:
        if obj.get("type") not in software_types:
            continue
        software_id = _external_id(obj)
        if not software_id:
            _logger.warning("mitre_object_skipped", reason="missing software external id")
            continue
        id_map[obj["id"]] = software_id
        parsed.append(
            MitreSoftware(
                software_id=software_id,
                name=obj.get("name", ""),
                description=obj.get("description", ""),
                is_malware=obj["type"] == MitreObjectType.SOFTWARE_MALWARE.value,
                attack_spec_version=version,
            )
        )
    return parsed


def _parse_groups(
    objects: list[dict[str, Any]], version: str, id_map: dict[str, str]
) -> list[MitreGroup]:
    parsed: list[MitreGroup] = []
    for obj in objects:
        if obj.get("type") != MitreObjectType.GROUP.value:
            continue
        group_id = _external_id(obj)
        if not group_id:
            _logger.warning("mitre_object_skipped", reason="missing group external id")
            continue
        id_map[obj["id"]] = group_id
        parsed.append(
            MitreGroup(
                group_id=group_id,
                name=obj.get("name", ""),
                description=obj.get("description", ""),
                attack_spec_version=version,
            )
        )
    return parsed


def _parse_mitigations(
    objects: list[dict[str, Any]], version: str, id_map: dict[str, str]
) -> list[MitreMitigation]:
    parsed: list[MitreMitigation] = []
    for obj in objects:
        if obj.get("type") != MitreObjectType.MITIGATION.value:
            continue
        mitigation_id = _external_id(obj)
        if not mitigation_id:
            _logger.warning("mitre_object_skipped", reason="missing mitigation external id")
            continue
        id_map[obj["id"]] = mitigation_id
        parsed.append(
            MitreMitigation(
                mitigation_id=mitigation_id,
                name=obj.get("name", ""),
                description=obj.get("description", ""),
                attack_spec_version=version,
            )
        )
    return parsed


def _parse_relationships(
    objects: list[dict[str, Any]], version: str, id_map: dict[str, str]
) -> list[MitreRelationship]:
    """Relationships are parsed last, once every other object type has
    populated `id_map` — a relationship referencing an object type this
    loader doesn't model (or that failed its own parse) is skipped, never
    raised, since STIX bundles routinely contain relationships to
    unmodeled object types (identities, marking-definitions, campaigns)."""
    parsed: list[MitreRelationship] = []
    known_types = {rel_type.value for rel_type in MitreRelationshipType}
    for obj in objects:
        if obj.get("type") != MitreObjectType.RELATIONSHIP.value:
            continue
        relationship_type = obj.get("relationship_type")
        if relationship_type not in known_types:
            continue
        source_business_id = id_map.get(obj.get("source_ref", ""))
        target_business_id = id_map.get(obj.get("target_ref", ""))
        if not source_business_id or not target_business_id:
            continue
        parsed.append(
            MitreRelationship(
                relationship_type=MitreRelationshipType(relationship_type),
                source_id=source_business_id,
                target_id=target_business_id,
                description=obj.get("description", ""),
                attack_spec_version=version,
            )
        )
    return parsed
