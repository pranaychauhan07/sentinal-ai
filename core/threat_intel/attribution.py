"""Evidence Attribution Layer — ties every persisted IOC back to the exact
evidence artifact and line(s) it was observed in. This is the explainability
audit trail blueprint §1 requires ("every step justified in plain language")
applied to threat intelligence specifically, distinct from
`core.parsers.audit.log_evidence_audit_event` (which logs ingestion actions,
not per-IOC provenance).
"""

from __future__ import annotations

from datetime import UTC, datetime

from core.threat_intel.models import AttributionRecord, IOCRecord


class EvidenceAttributionTracker:
    """Stateless: builds one `AttributionRecord` per deduplicated
    `IOCRecord`, reading the line-number history `core.threat_intel.dedup.
    deduplicate_iocs` accumulates into `IOCRecord.context['line_numbers']`."""

    def attribute(self, iocs: list[IOCRecord]) -> list[AttributionRecord]:
        return [self._attribute_one(ioc) for ioc in iocs]

    def _attribute_one(self, ioc: IOCRecord) -> AttributionRecord:
        line_numbers = tuple(ioc.context.get("line_numbers", []))
        if not line_numbers and ioc.line_number is not None:
            line_numbers = (ioc.line_number,)
        now = datetime.now(UTC)
        return AttributionRecord(
            ioc_id=ioc.ioc_id,
            evidence_id=ioc.evidence_id,
            source=ioc.source,
            line_numbers=line_numbers,
            occurrence_count=max(1, len(line_numbers)),
            first_seen=ioc.first_seen,
            last_seen=now,
        )
