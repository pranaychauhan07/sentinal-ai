"""`MitreLookup` — fast, in-memory technique/tactic/software/group/mitigation
lookups the Finding & MITRE ATT&CK Intelligence Engine's mapping engine
needs beyond `KnowledgeSource.search()`'s generic keyword interface (that
Protocol stays generic per `core/knowledge/interfaces.py`; this module is
the narrow, MITRE-specific seam `core.findings.mapping_engine` actually
calls, matching constitution §1.3's "small, focused modules").

Stateless with respect to mutation: built once from a loaded
:class:`core.knowledge.mitre.models.MitreDataset` and never mutated — a new
ATT&CK version is a new `MitreLookup` instance, never an in-place update.
"""

from __future__ import annotations

from core.knowledge.mitre.exceptions import UnknownTechniqueError
from core.knowledge.mitre.models import (
    MitreDataset,
    MitreGroup,
    MitreMitigation,
    MitreRelationshipType,
    MitreSoftware,
    MitreTactic,
    MitreTechnique,
)


class MitreLookup:
    """Indexes one `MitreDataset` for O(1) lookups by business ID and O(1)
    (amortized) reverse lookups by tag/tactic/technique."""

    def __init__(self, dataset: MitreDataset) -> None:
        self.dataset = dataset
        self._techniques_by_id = {t.technique_id: t for t in dataset.techniques}
        self._tactics_by_shortname = {t.shortname: t for t in dataset.tactics}
        self._software_by_id = {s.software_id: s for s in dataset.software}
        self._groups_by_id = {g.group_id: g for g in dataset.groups}
        self._mitigations_by_id = {m.mitigation_id: m for m in dataset.mitigations}

        self._techniques_used_by_group: dict[str, tuple[str, ...]] = {}
        self._techniques_used_by_software: dict[str, tuple[str, ...]] = {}
        self._mitigations_for_technique: dict[str, tuple[str, ...]] = {}
        self._software_used_by_group: dict[str, tuple[str, ...]] = {}
        for rel in dataset.relationships:
            if rel.relationship_type is MitreRelationshipType.USES:
                if rel.source_id in self._groups_by_id and rel.target_id in self._techniques_by_id:
                    self._techniques_used_by_group[rel.source_id] = (
                        *self._techniques_used_by_group.get(rel.source_id, ()),
                        rel.target_id,
                    )
                if rel.source_id in self._groups_by_id and rel.target_id in self._software_by_id:
                    self._software_used_by_group[rel.source_id] = (
                        *self._software_used_by_group.get(rel.source_id, ()),
                        rel.target_id,
                    )
                if (
                    rel.source_id in self._software_by_id
                    and rel.target_id in self._techniques_by_id
                ):
                    self._techniques_used_by_software[rel.source_id] = (
                        *self._techniques_used_by_software.get(rel.source_id, ()),
                        rel.target_id,
                    )
            elif rel.relationship_type is MitreRelationshipType.MITIGATES:
                if (
                    rel.source_id in self._mitigations_by_id
                    and rel.target_id in self._techniques_by_id
                ):
                    self._mitigations_for_technique[rel.target_id] = (
                        *self._mitigations_for_technique.get(rel.target_id, ()),
                        rel.source_id,
                    )

    def technique_by_id(self, technique_id: str) -> MitreTechnique:
        technique = self._techniques_by_id.get(technique_id)
        if technique is None:
            raise UnknownTechniqueError(
                f"No MITRE technique {technique_id!r} in loaded dataset "
                f"(attack_spec_version={self.dataset.attack_spec_version!r}).",
                details={"technique_id": technique_id},
            )
        return technique

    def has_technique(self, technique_id: str) -> bool:
        return technique_id in self._techniques_by_id

    def tactics_for_technique(self, technique_id: str) -> tuple[MitreTactic, ...]:
        technique = self.technique_by_id(technique_id)
        return tuple(
            self._tactics_by_shortname[shortname]
            for shortname in technique.tactic_shortnames
            if shortname in self._tactics_by_shortname
        )

    def mitigations_for_technique(self, technique_id: str) -> tuple[MitreMitigation, ...]:
        mitigation_ids = self._mitigations_for_technique.get(technique_id, ())
        return tuple(self._mitigations_by_id[mid] for mid in mitigation_ids)

    def groups_using_technique(self, technique_id: str) -> tuple[MitreGroup, ...]:
        return tuple(
            self._groups_by_id[group_id]
            for group_id, technique_ids in self._techniques_used_by_group.items()
            if technique_id in technique_ids
        )

    def software_using_technique(self, technique_id: str) -> tuple[MitreSoftware, ...]:
        return tuple(
            self._software_by_id[software_id]
            for software_id, technique_ids in self._techniques_used_by_software.items()
            if technique_id in technique_ids
        )

    def all_technique_ids(self) -> tuple[str, ...]:
        return tuple(self._techniques_by_id.keys())
