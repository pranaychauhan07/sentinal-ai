"""`DetectionRuleSource` — the concrete `KnowledgeSource` for
`KnowledgeSourceType.DETECTION_RULE` (ADR-0027). General detection-
engineering principles/guidance, structurally independent of
`core/findings/mapping_rules.py`.
"""

from __future__ import annotations

from core.knowledge.detection.models import DetectionPrinciple
from core.knowledge.models import (
    KnowledgeDocument,
    KnowledgeQuery,
    KnowledgeSearchResult,
    KnowledgeSourceType,
)
from core.knowledge.retrieval import KeywordKnowledgeRetriever


class DetectionRuleSource:
    """Satisfies `KnowledgeSource` for `DETECTION_RULE`."""

    source_type = KnowledgeSourceType.DETECTION_RULE.value

    def __init__(self, principles: tuple[DetectionPrinciple, ...]) -> None:
        self._documents: dict[str, KnowledgeDocument] = {
            principle.id: KnowledgeDocument(
                id=principle.id,
                source_type=KnowledgeSourceType.DETECTION_RULE,
                title=principle.title,
                content=principle.guidance,
                tags=("detection_engineering",),
                metadata={"object_type": "detection_principle"},
            )
            for principle in principles
        }

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
