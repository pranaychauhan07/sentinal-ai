"""`SecurityPlaybookSource` — the concrete `KnowledgeSource` for
`KnowledgeSourceType.SECURITY_PLAYBOOK` (ADR-0027), combining general
security best practices and NIST SP 800-61 incident-response guidance into
one source (both are general, non-case-specific playbook/guidance content —
the same taxonomy slot, per ADR-0027's Decision 4).
"""

from __future__ import annotations

from core.knowledge.models import (
    KnowledgeDocument,
    KnowledgeQuery,
    KnowledgeSearchResult,
    KnowledgeSourceType,
)
from core.knowledge.playbooks.models import BestPracticeEntry, IncidentResponsePhaseGuidance
from core.knowledge.retrieval import KeywordKnowledgeRetriever


class SecurityPlaybookSource:
    """Satisfies `KnowledgeSource` for `SECURITY_PLAYBOOK`."""

    source_type = KnowledgeSourceType.SECURITY_PLAYBOOK.value

    def __init__(
        self,
        *,
        best_practices: tuple[BestPracticeEntry, ...],
        incident_response_phases: tuple[IncidentResponsePhaseGuidance, ...],
    ) -> None:
        self._documents: dict[str, KnowledgeDocument] = {}
        for practice in best_practices:
            self._documents[practice.id] = KnowledgeDocument(
                id=practice.id,
                source_type=KnowledgeSourceType.SECURITY_PLAYBOOK,
                title=practice.title,
                content=practice.guidance,
                tags=("best_practice", practice.category),
                metadata={"object_type": "best_practice", "category": practice.category},
            )
        for phase in incident_response_phases:
            self._documents[phase.id] = KnowledgeDocument(
                id=phase.id,
                source_type=KnowledgeSourceType.SECURITY_PLAYBOOK,
                title=phase.phase,
                content=phase.guidance,
                tags=("incident_response", "nist_800_61"),
                metadata={"object_type": "incident_response_phase"},
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
