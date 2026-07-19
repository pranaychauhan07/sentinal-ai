"""`FindingDeduplicationEngine` — decides whether a candidate Finding is new
or should merge into an existing open Finding for the same case, across six
dimensions the task requires: hash similarity, IOC overlap, technique
overlap, evidence overlap, time-window proximity, and host overlap.

Scoped to *within* one case's open Findings — never cross-case (ADR-0013's
explicit scope cut, matching `core.threat_intel.dedup`'s identical scoping).

**Performance:** bucket-first, not naive pairwise (constitution §10,
"protect against duplicate explosions"). `evaluate()` cheaply pre-filters
`existing_findings` down to only those sharing at least one IOC, technique,
or affected asset with the candidate before computing the full six-
dimension similarity score — the expensive comparison only ever runs
against genuinely-overlapping candidates, keeping the common "no overlap"
case O(1) per existing Finding rather than a constant-factor-heavy full
score.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta

from core.findings.models import (
    DedupDecision,
    DuplicateMatchResult,
    FindingRecord,
    FindingStatus,
    MitreMapping,
    TimelineEntry,
)
from core.findings.severity import SEVERITY_ORDER

# Equal weighting across all six required dimensions — kept as named
# constants (constitution §2, "Constants") rather than inline literals so a
# future tuning pass has one place to change them.
_WEIGHT_HASH = 1 / 6
_WEIGHT_IOC_OVERLAP = 1 / 6
_WEIGHT_TECHNIQUE_OVERLAP = 1 / 6
_WEIGHT_EVIDENCE_OVERLAP = 1 / 6
_WEIGHT_TIME_WINDOW = 1 / 6
_WEIGHT_HOST_OVERLAP = 1 / 6


def _content_hash(technique_ids: tuple[str, ...], ioc_ids: tuple[str, ...]) -> str:
    canonical = "|".join(sorted(technique_ids)) + "::" + "|".join(sorted(ioc_ids))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _jaccard(a: frozenset[uuid.UUID | str], b: frozenset[uuid.UUID | str]) -> float:
    """Two empty sets score 1.0 (neither side contradicts the other — no
    signal is treated as agreement, not disagreement), matching how this
    dimension is meant to behave when, e.g., neither the candidate nor the
    existing Finding has any linked evidence artifacts yet. One empty and
    one non-empty set scores 0.0 — that *is* a real difference."""
    if not a and not b:
        return 1.0
    union = a | b
    if not union:
        return 1.0
    return len(a & b) / len(union)


class FindingDeduplicationEngine:
    def __init__(self, *, time_window_minutes: int = 60) -> None:
        self._time_window = timedelta(minutes=time_window_minutes)

    def evaluate(
        self,
        *,
        candidate_ioc_ids: tuple[uuid.UUID, ...],
        candidate_evidence_ids: tuple[uuid.UUID, ...],
        candidate_mappings: list[MitreMapping],
        candidate_affected_assets: tuple[str, ...],
        candidate_first_seen: datetime,
        candidate_last_seen: datetime,
        existing_findings: list[FindingRecord],
        similarity_threshold: float,
    ) -> DuplicateMatchResult:
        candidate_ioc_set = frozenset(candidate_ioc_ids)
        candidate_evidence_set = frozenset(candidate_evidence_ids)
        candidate_technique_ids = tuple(mapping.technique_id for mapping in candidate_mappings)
        candidate_technique_set = frozenset(candidate_technique_ids)
        candidate_asset_set = frozenset(candidate_affected_assets)
        candidate_hash = _content_hash(
            candidate_technique_ids, tuple(str(i) for i in candidate_ioc_ids)
        )

        best_match: DuplicateMatchResult | None = None
        for existing in existing_findings:
            existing_ioc_set = frozenset(existing.ioc_refs)
            existing_technique_set = frozenset(existing.mapped_technique_ids)
            existing_asset_set = frozenset(existing.affected_assets)

            # Bucket-first pre-filter: skip the expensive scoring entirely
            # for a Finding sharing nothing with the candidate.
            if not (
                (candidate_ioc_set & existing_ioc_set)
                or (candidate_technique_set & existing_technique_set)
                or (candidate_asset_set & existing_asset_set)
            ):
                continue

            technique_overlap = _jaccard(candidate_technique_set, existing_technique_set)
            if candidate_technique_set and existing_technique_set and technique_overlap == 0.0:
                # Two Findings mapped to entirely disjoint technique sets
                # are never merge candidates, however much of their
                # supporting evidence otherwise overlaps — this is exactly
                # the "one IOC, many techniques" case the mapping engine
                # deliberately produces as separate Findings, not a
                # duplicate of itself.
                continue

            existing_evidence_set = frozenset(existing.evidence_refs)
            existing_hash = _content_hash(
                existing.mapped_technique_ids, tuple(str(i) for i in existing.ioc_refs)
            )

            hash_score = 1.0 if candidate_hash == existing_hash else 0.0
            ioc_overlap = _jaccard(candidate_ioc_set, existing_ioc_set)
            evidence_overlap = _jaccard(candidate_evidence_set, existing_evidence_set)
            host_overlap = _jaccard(candidate_asset_set, existing_asset_set)
            time_window_score = self._time_window_score(
                candidate_first_seen, candidate_last_seen, existing.timeline
            )

            similarity = (
                _WEIGHT_HASH * hash_score
                + _WEIGHT_IOC_OVERLAP * ioc_overlap
                + _WEIGHT_TECHNIQUE_OVERLAP * technique_overlap
                + _WEIGHT_EVIDENCE_OVERLAP * evidence_overlap
                + _WEIGHT_TIME_WINDOW * time_window_score
                + _WEIGHT_HOST_OVERLAP * host_overlap
            )

            if best_match is None or similarity > best_match.similarity_score:
                best_match = DuplicateMatchResult(
                    decision=DedupDecision.NEW,
                    matched_finding_id=existing.finding_id,
                    similarity_score=similarity,
                    matched_dimensions={
                        "hash": hash_score,
                        "ioc_overlap": ioc_overlap,
                        "technique_overlap": technique_overlap,
                        "evidence_overlap": evidence_overlap,
                        "time_window": time_window_score,
                        "host_overlap": host_overlap,
                    },
                    reason=f"similarity {similarity:.3f} against Finding {existing.finding_id}",
                )

        if best_match is not None and best_match.similarity_score >= similarity_threshold:
            return best_match.model_copy(update={"decision": DedupDecision.MERGE})
        if best_match is not None:
            return best_match
        return DuplicateMatchResult(
            decision=DedupDecision.NEW, reason="no overlapping Finding found"
        )

    def _time_window_score(
        self,
        candidate_first_seen: datetime,
        candidate_last_seen: datetime,
        existing_timeline: tuple[TimelineEntry, ...],
    ) -> float:
        if not existing_timeline:
            return 0.0
        existing_first = min(entry.occurred_at for entry in existing_timeline)
        existing_last = max(entry.occurred_at for entry in existing_timeline)
        # Overlapping ranges score 1.0; otherwise decay to 0.0 at exactly
        # one time-window's distance beyond the nearer edge.
        if candidate_first_seen <= existing_last and candidate_last_seen >= existing_first:
            return 1.0
        gap = (
            candidate_first_seen - existing_last
            if candidate_first_seen > existing_last
            else existing_first - candidate_last_seen
        )
        if gap >= self._time_window:
            return 0.0
        return 1.0 - (gap / self._time_window)


def merge_findings(existing: FindingRecord, incoming: FindingRecord) -> FindingRecord:
    """Union an incoming candidate Finding into an already-persisted one —
    never drops evidence (constitution §1.7): every evidence/IOC reference,
    mapping, and timeline entry from both Findings is preserved. The higher
    severity/confidence/risk score wins; a `CLOSED` Finding that receives new
    supporting evidence is reopened, since new evidence is grounds to
    reconsider a closed decision, never silently discarded."""
    merged_severity = max(existing.severity, incoming.severity, key=SEVERITY_ORDER.index)
    merged_confidence = (
        existing.confidence
        if existing.confidence.composite >= incoming.confidence.composite
        else incoming.confidence
    )
    merged_evidence_refs = tuple(dict.fromkeys((*existing.evidence_refs, *incoming.evidence_refs)))
    merged_ioc_refs = tuple(dict.fromkeys((*existing.ioc_refs, *incoming.ioc_refs)))
    existing_technique_ids = {m.technique_id for m in existing.mitre_mappings}
    merged_mappings = (
        *existing.mitre_mappings,
        *(m for m in incoming.mitre_mappings if m.technique_id not in existing_technique_ids),
    )
    merged_timeline = tuple(
        sorted({*existing.timeline, *incoming.timeline}, key=lambda entry: entry.occurred_at)
    )
    merged_assets = tuple(dict.fromkeys((*existing.affected_assets, *incoming.affected_assets)))

    return existing.model_copy(
        update={
            "severity": merged_severity,
            "confidence": merged_confidence,
            "status": (
                FindingStatus.OPEN if existing.status == FindingStatus.CLOSED else existing.status
            ),
            "evidence_refs": merged_evidence_refs,
            "ioc_refs": merged_ioc_refs,
            "mitre_mappings": merged_mappings,
            "timeline": merged_timeline,
            "affected_assets": merged_assets,
            "risk_score": max(existing.risk_score, incoming.risk_score),
            "updated_at": datetime.now(UTC),
        }
    )
