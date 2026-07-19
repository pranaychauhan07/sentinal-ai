"""`EvidenceAggregator` — groups a Finding candidate's `ScoredIOC`s into one
`EvidenceBundle`: cross-reference tracking (which evidence/IOC IDs back this
Finding), timeline reconstruction, and affected-asset extraction. Preserves
chain of custody by carrying forward each IOC's existing
`AttributionRecord` unchanged — never re-deriving or discarding it (task
requirement: "Chain of custody preservation").

Scoped to *within* one case's candidate set, exactly like
`core.threat_intel.dedup.deduplicate_iocs` — this is not cross-case
correlation (ADR-0013's explicit scope cut).
"""

from __future__ import annotations

from core.findings.models import EvidenceBundle, TimelineEntry
from core.threat_intel.models import IOCType, ScoredIOC

#: IOC types treated as "an affected asset" for the Finding's
#: `affected_assets` field — hosts and endpoints, not every indicator type.
ASSET_IOC_TYPES = frozenset({IOCType.HOSTNAME, IOCType.IPV4, IOCType.IPV6})


class EvidenceAggregator:
    """Stateless: builds one `EvidenceBundle` per candidate IOC group."""

    def aggregate(self, iocs: list[ScoredIOC]) -> EvidenceBundle:
        if not iocs:
            raise ValueError("EvidenceAggregator.aggregate requires at least one ScoredIOC.")

        ioc_ids = tuple(ioc.record.ioc_id for ioc in iocs)
        evidence_ids = tuple(
            dict.fromkeys(
                ioc.attribution.evidence_id
                for ioc in iocs
                if ioc.attribution.evidence_id is not None
            )
        )
        affected_assets = tuple(
            dict.fromkeys(
                ioc.record.value for ioc in iocs if ioc.record.ioc_type in ASSET_IOC_TYPES
            )
        )
        timeline = self._build_timeline(iocs)
        first_seen = min(ioc.attribution.first_seen for ioc in iocs)
        last_seen = max(ioc.attribution.last_seen for ioc in iocs)

        return EvidenceBundle(
            ioc_ids=ioc_ids,
            evidence_ids=evidence_ids,
            affected_assets=affected_assets,
            timeline=timeline,
            first_seen=first_seen,
            last_seen=last_seen,
        )

    @staticmethod
    def _build_timeline(iocs: list[ScoredIOC]) -> tuple[TimelineEntry, ...]:
        entries = [
            TimelineEntry(
                occurred_at=ioc.attribution.first_seen,
                ioc_id=ioc.record.ioc_id,
                evidence_id=ioc.attribution.evidence_id,
                description=(
                    f"{ioc.record.ioc_type.value} '{ioc.record.value}' observed in "
                    f"{ioc.record.source}"
                ),
            )
            for ioc in iocs
        ]
        entries.sort(key=lambda entry: entry.occurred_at)
        return tuple(entries)
