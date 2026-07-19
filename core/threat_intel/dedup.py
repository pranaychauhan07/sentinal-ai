"""IOC deduplication — collapses repeated observations of the same
indicator within one extraction run into a single `IOCRecord`, never
dropping provenance (constitution §1.7): merged tags accumulate, the
earliest `first_seen` wins, and the highest observed `confidence` is kept.

Scoped to *within* one extraction run's candidate set, per docs/adr/0012's
explicit scope cut — this is not cross-case/cross-evidence correlation.
"""

from __future__ import annotations

from core.threat_intel.models import IOCRecord, IOCType


def _dedup_key(ioc: IOCRecord) -> tuple[IOCType, str]:
    return (ioc.ioc_type, ioc.value)


def deduplicate_iocs(candidates: list[IOCRecord]) -> list[IOCRecord]:
    """Merge candidates sharing the same `(ioc_type, value)` key. Order of
    first appearance is preserved for the merged result."""
    merged: dict[tuple[IOCType, str], IOCRecord] = {}
    order: list[tuple[IOCType, str]] = []

    for candidate in candidates:
        key = _dedup_key(candidate)
        existing = merged.get(key)
        if existing is None:
            merged[key] = candidate
            order.append(key)
            continue
        merged[key] = _merge(existing, candidate)

    return [merged[key] for key in order]


def _merge(existing: IOCRecord, incoming: IOCRecord) -> IOCRecord:
    merged_tags = tuple(dict.fromkeys((*existing.tags, *incoming.tags)))
    line_numbers_context = existing.context.get("line_numbers", [])
    if existing.line_number is not None and existing.line_number not in line_numbers_context:
        line_numbers_context = [*line_numbers_context, existing.line_number]
    if incoming.line_number is not None and incoming.line_number not in line_numbers_context:
        line_numbers_context = [*line_numbers_context, incoming.line_number]

    return existing.model_copy(
        update={
            "confidence": max(existing.confidence, incoming.confidence),
            "first_seen": min(existing.first_seen, incoming.first_seen),
            "tags": merged_tags,
            "context": {**existing.context, "line_numbers": line_numbers_context},
        }
    )
