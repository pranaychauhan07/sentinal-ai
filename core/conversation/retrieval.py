"""`RetrievalLayer` — the task's named "Retrieval Layer" requirement.

Turns an already-hydrated `ConversationRetrievalContext` (Findings/IOCs/
MITRE mappings/Reports/Timeline events, as plain dicts —
`core/services/conversation_service.py`'s job to fetch, never this
package's) into scored, citable `RetrievedItem`s. Never queries a database
itself (constitution §3: leaves never call up, and this leaf specifically
stays `core/db`-free per docs/adr/0025 Decision 1) and never re-derives a
severity/risk/confidence score (constitution §1.9) — relevance scoring here
is plain keyword overlap against the question, a fixed and checkable
function, not a re-scoring of the underlying finding.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from core.conversation.exceptions import OversizedConversationInputError
from core.conversation.models import (
    ConversationRetrievalContext,
    EvidenceCategory,
    RetrievedItem,
    SourceReference,
)

#: Resource-exhaustion guard (constitution §5, "Timeouts"/"Oversized input
#: guard" precedent from `core.owasp_security.exceptions.
#: OversizedSourceInputError`) — a pathologically large case should fail
#: fast and loud, not silently degrade retrieval quality by truncation.
MAX_RECORDS_PER_CATEGORY = 5_000

_WORD_PATTERN = re.compile(r"[a-z0-9]+")


def _tokenize(text: str) -> set[str]:
    return set(_WORD_PATTERN.findall(text.lower()))


def _relevance_score(question_tokens: set[str], text: str) -> float:
    """Deterministic keyword-overlap relevance in `[0.0, 1.0]` — the
    Jaccard-style overlap between the question's tokens and the candidate
    text's tokens. Not semantic search (that's a future, real-embedding
    upgrade behind the same `RetrievedItem` shape); a fixed, checkable
    function, never an LLM's job (constitution §1.9)."""
    if not question_tokens:
        return 0.0
    candidate_tokens = _tokenize(text)
    if not candidate_tokens:
        return 0.0
    overlap = question_tokens & candidate_tokens
    if not overlap:
        return 0.0
    return min(1.0, len(overlap) / len(question_tokens))


def _finding_text(record: dict[str, object]) -> str:
    parts = [
        str(record.get("title", "")),
        str(record.get("description", "")),
        str(record.get("severity", "")),
    ]
    return " ".join(p for p in parts if p)


def _finding_summary(record: dict[str, object]) -> str:
    title = str(record.get("title", "untitled finding"))
    severity = str(record.get("severity", "unknown"))
    return f"Finding '{title}' (severity: {severity})"


def _ioc_text(record: dict[str, object]) -> str:
    return f"{record.get('ioc_type', '')} {record.get('value', '')}"


def _ioc_summary(record: dict[str, object]) -> str:
    ioc_type = str(record.get("ioc_type", "unknown"))
    value = str(record.get("value", ""))
    return f"IOC {ioc_type}: {value}"


def _mitre_text(record: dict[str, object]) -> str:
    tactic_ids = record.get("tactic_ids", [])
    tactic_text = " ".join(str(t) for t in tactic_ids) if isinstance(tactic_ids, list) else ""
    return f"{record.get('technique_id', '')} {tactic_text}"


def _mitre_summary(record: dict[str, object]) -> str:
    technique_id = str(record.get("technique_id", "unknown"))
    return f"MITRE ATT&CK technique {technique_id}"


def _report_text(record: dict[str, object]) -> str:
    return f"{record.get('title', '')} {record.get('report_type', '')}"


def _report_summary(record: dict[str, object]) -> str:
    title = str(record.get("title", "untitled report"))
    return f"Report '{title}'"


def _timeline_text(record: dict[str, object]) -> str:
    return str(record.get("narrative", ""))


def _timeline_summary(record: dict[str, object]) -> str:
    event_type = str(record.get("event_type", "event"))
    narrative = str(record.get("narrative", ""))
    return f"Timeline event ({event_type}): {narrative}"


_TextExtractor = Callable[[dict[str, object]], str]

#: One (id-key, text-extractor, summary-extractor) tuple per category — the
#: single table this module's `retrieve` loop drives from, so adding a new
#: retrievable category is a one-line addition here, not a new branch
#: scattered through the function body.
_CATEGORY_EXTRACTORS: dict[EvidenceCategory, tuple[str, _TextExtractor, _TextExtractor]] = {
    EvidenceCategory.FINDING: ("finding_id", _finding_text, _finding_summary),
    EvidenceCategory.IOC: ("ioc_id", _ioc_text, _ioc_summary),
    EvidenceCategory.MITRE_MAPPING: ("technique_id", _mitre_text, _mitre_summary),
    EvidenceCategory.REPORT: ("report_id", _report_text, _report_summary),
    EvidenceCategory.TIMELINE_EVENT: ("event_id", _timeline_text, _timeline_summary),
}


def _records_for_category(
    context: ConversationRetrievalContext, category: EvidenceCategory
) -> tuple[dict[str, object], ...]:
    return {
        EvidenceCategory.FINDING: context.findings,
        EvidenceCategory.IOC: context.iocs,
        EvidenceCategory.MITRE_MAPPING: context.mitre_mappings,
        EvidenceCategory.REPORT: context.reports,
        EvidenceCategory.TIMELINE_EVENT: context.timeline_events,
    }[category]


class RetrievalLayer:
    """Deterministic, keyword-scored retrieval over already-hydrated case
    data. Stateless — every method is a pure function of its arguments."""

    def retrieve(
        self,
        context: ConversationRetrievalContext,
        *,
        question: str,
        categories: tuple[EvidenceCategory, ...],
    ) -> list[RetrievedItem]:
        question_tokens = _tokenize(question)
        items: list[RetrievedItem] = []
        for category in categories:
            records = _records_for_category(context, category)
            if len(records) > MAX_RECORDS_PER_CATEGORY:
                raise OversizedConversationInputError(
                    f"Case {context.case_id} has {len(records)} {category.value} records, "
                    f"exceeding the maximum of {MAX_RECORDS_PER_CATEGORY}.",
                    details={"category": category.value, "count": len(records)},
                )
            id_key, text_fn, summary_fn = _CATEGORY_EXTRACTORS[category]
            for index, record in enumerate(records):
                if not isinstance(record, dict):
                    continue
                source_id = str(record.get(id_key) or f"{category.value}-{index}")
                text = text_fn(record)
                score = _relevance_score(question_tokens, text)
                if score <= 0.0:
                    continue
                items.append(
                    RetrievedItem(
                        category=category,
                        source_id=source_id,
                        text=text,
                        relevance_score=score,
                        reference=SourceReference(
                            category=category,
                            source_id=source_id,
                            summary=summary_fn(record),
                        ),
                    )
                )
        return items
