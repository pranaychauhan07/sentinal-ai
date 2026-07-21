"""`ToolSelectionEngine` — the task's named "Tool Selection Engine".

Deterministically decides which case-data categories (`EvidenceCategory`)
a question needs retrieval over, from keyword rules — a fixed, checkable
function (constitution §1.9), never an LLM's job. "Tools" here means
retrieval categories, not `core/tools/*.py` registered functions: this
assistant answers questions from already-persisted case data; it never
triggers a new analysis run (docs/adr/0025 Decision 5's "never bypasses the
deterministic pipeline").
"""

from __future__ import annotations

import re

from core.conversation.models import EvidenceCategory, ToolSelection

#: Keyword group -> category it routes to. Checked in this fixed order so
#: the emitted `thought` is deterministic and reproducible for the same
#: question (constitution §5, "Deterministic outputs").
_CATEGORY_KEYWORDS: tuple[tuple[EvidenceCategory, tuple[str, ...]], ...] = (
    (
        EvidenceCategory.IOC,
        ("ioc", "indicator", "ip address", "domain", "hash", "malicious ip"),
    ),
    (
        EvidenceCategory.MITRE_MAPPING,
        ("mitre", "att&ck", "attack", "technique", "tactic", "ttps"),
    ),
    (
        EvidenceCategory.REPORT,
        ("report", "executive summary", "assessment"),
    ),
    (
        EvidenceCategory.TIMELINE_EVENT,
        ("timeline", "when did", "sequence of events", "chronolog"),
    ),
    (
        EvidenceCategory.FINDING,
        ("finding", "vulnerab", "severity", "risk score", "why was", "explain"),
    ),
)

_ALL_CATEGORIES: tuple[EvidenceCategory, ...] = tuple(
    category for category, _ in _CATEGORY_KEYWORDS
)


class ToolSelectionEngine:
    """Stateless keyword router from question text to retrieval categories."""

    def select(self, question: str) -> ToolSelection:
        lowered = question.lower()
        matched: list[EvidenceCategory] = []
        matched_keywords: list[str] = []
        for category, keywords in _CATEGORY_KEYWORDS:
            for keyword in keywords:
                if re.search(re.escape(keyword), lowered):
                    matched.append(category)
                    matched_keywords.append(keyword)
                    break

        if not matched:
            return ToolSelection(
                categories=_ALL_CATEGORIES,
                thought=(
                    "No specific category keywords matched the question; "
                    "searching every available evidence category."
                ),
            )

        return ToolSelection(
            categories=tuple(matched),
            thought=(
                f"Matched keyword(s) {', '.join(matched_keywords)}; "
                f"searching {', '.join(c.value for c in matched)}."
            ),
        )
