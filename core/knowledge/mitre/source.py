"""`MitreAttackSource` — the concrete `core.knowledge.interfaces.
KnowledgeSource` implementation ADR-0010 reserved
`KnowledgeSourceType.MITRE_ATTACK` for. Wraps one loaded
`core.knowledge.mitre.models.MitreDataset` in-memory; built once at process
startup from the vendored bundle (`core.knowledge.mitre.loader`), never
re-read per request.
"""

from __future__ import annotations

from core.knowledge.mitre.models import MitreDataset
from core.knowledge.models import (
    KnowledgeDocument,
    KnowledgeQuery,
    KnowledgeSearchResult,
    KnowledgeSourceType,
)
from core.knowledge.retrieval import KeywordKnowledgeRetriever


class MitreAttackSource:
    """Satisfies `core.knowledge.interfaces.KnowledgeSource` for the MITRE
    ATT&CK domain. Every technique/tactic/software/group/mitigation in the
    loaded dataset is exposed as one `KnowledgeDocument`, keyed by its
    business ID (e.g. `T1110`, `TA0006`, `S0002`, `G0007`, `M1032`) — these
    IDs never collide across categories, so `get()` can search all five
    without a category prefix argument."""

    source_type = KnowledgeSourceType.MITRE_ATTACK.value

    def __init__(self, dataset: MitreDataset) -> None:
        self._dataset = dataset
        self._documents: dict[str, KnowledgeDocument] = {}
        for tactic in dataset.tactics:
            self._documents[tactic.tactic_id] = KnowledgeDocument(
                id=tactic.tactic_id,
                source_type=KnowledgeSourceType.MITRE_ATTACK,
                title=tactic.name,
                content=tactic.description,
                tags=(tactic.shortname,),
                metadata={
                    "object_type": "tactic",
                    "attack_spec_version": tactic.attack_spec_version,
                },
            )
        for technique in dataset.techniques:
            self._documents[technique.technique_id] = KnowledgeDocument(
                id=technique.technique_id,
                source_type=KnowledgeSourceType.MITRE_ATTACK,
                title=technique.name,
                content=technique.description,
                tags=technique.tactic_shortnames,
                metadata={
                    "object_type": "technique",
                    "attack_spec_version": technique.attack_spec_version,
                    "platforms": list(technique.platforms),
                },
            )
        for software in dataset.software:
            self._documents[software.software_id] = KnowledgeDocument(
                id=software.software_id,
                source_type=KnowledgeSourceType.MITRE_ATTACK,
                title=software.name,
                content=software.description,
                tags=("malware" if software.is_malware else "tool",),
                metadata={
                    "object_type": "software",
                    "attack_spec_version": software.attack_spec_version,
                },
            )
        for group in dataset.groups:
            self._documents[group.group_id] = KnowledgeDocument(
                id=group.group_id,
                source_type=KnowledgeSourceType.MITRE_ATTACK,
                title=group.name,
                content=group.description,
                tags=("group",),
                metadata={"object_type": "group", "attack_spec_version": group.attack_spec_version},
            )
        for mitigation in dataset.mitigations:
            self._documents[mitigation.mitigation_id] = KnowledgeDocument(
                id=mitigation.mitigation_id,
                source_type=KnowledgeSourceType.MITRE_ATTACK,
                title=mitigation.name,
                content=mitigation.description,
                tags=("mitigation",),
                metadata={
                    "object_type": "mitigation",
                    "attack_spec_version": mitigation.attack_spec_version,
                },
            )

    def get(self, document_id: str) -> KnowledgeDocument | None:
        return self._documents.get(document_id)

    def search(self, query: KnowledgeQuery) -> list[KnowledgeSearchResult]:
        results: list[KnowledgeSearchResult] = []
        for document in self._documents.values():
            score = KeywordKnowledgeRetriever.score_text(
                query.text, f"{document.title} {document.content}"
            )
            if score > 0.0:
                results.append(KnowledgeSearchResult(document=document, score=score))
        results.sort(key=lambda result: result.score, reverse=True)
        return results[: query.limit]
