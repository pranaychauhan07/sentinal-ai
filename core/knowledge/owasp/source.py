"""`OwaspTop10Source` — the concrete `core.knowledge.interfaces.
KnowledgeSource` implementation ADR-0010 reserved
`KnowledgeSourceType.OWASP_TOP10` for (ADR-0027 fills it in). Mirrors
`core.knowledge.mitre.source.MitreAttackSource`'s shape exactly.
"""

from __future__ import annotations

from core.knowledge.models import (
    KnowledgeDocument,
    KnowledgeQuery,
    KnowledgeSearchResult,
    KnowledgeSourceType,
)
from core.knowledge.owasp.models import OwaspCategory
from core.knowledge.retrieval import KeywordKnowledgeRetriever


class OwaspTop10Source:
    """Satisfies `KnowledgeSource` for the OWASP Top 10:2021 taxonomy."""

    source_type = KnowledgeSourceType.OWASP_TOP10.value

    def __init__(self, categories: tuple[OwaspCategory, ...]) -> None:
        self._documents: dict[str, KnowledgeDocument] = {
            category.id: KnowledgeDocument(
                id=category.id,
                source_type=KnowledgeSourceType.OWASP_TOP10,
                title=category.name,
                content=f"{category.description}\n\nRemediation: {category.remediation}",
                tags=(category.id,),
                metadata={"remediation": category.remediation},
            )
            for category in categories
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
