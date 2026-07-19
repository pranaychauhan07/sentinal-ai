"""Finding-generation audit logging — the evidentiary/attribution trail
every Finding-lifecycle action leaves, mirroring
`core.threat_intel.audit.log_threat_intel_audit_event`'s "thin wrapper over
`core.logging`" pattern exactly, kept separate from `core/findings/events.py`
for the same reason `core/threat_intel/audit.py` is kept separate from
`core/threat_intel/events.py`: this is the evidentiary record (which
Finding, mapped to which technique, generated from which IOCs), trivially
greppable/filterable on its own event name.
"""

from __future__ import annotations

import uuid
from enum import StrEnum

from core.logging import get_logger

_logger = get_logger(__name__)


class FindingAuditAction(StrEnum):
    MAPPED = "mapped"
    AGGREGATED = "aggregated"
    SCORED = "scored"
    DEDUPLICATED = "deduplicated"
    MERGED = "merged"
    GENERATED = "generated"
    PERSISTED = "persisted"
    CLOSED = "closed"


def log_finding_audit_event(
    *,
    action: FindingAuditAction,
    finding_id: uuid.UUID | None,
    case_id: uuid.UUID,
    technique_id: str | None = None,
    detail: str = "",
) -> None:
    """Emit one structured, queryable audit log line. Never raises — an
    audit-logging failure must not abort Finding generation (constitution
    §9's degraded-not-fatal rule), matching
    `core.threat_intel.audit.log_threat_intel_audit_event`'s contract."""
    _logger.info(
        "finding_audit_event",
        action=action.value,
        finding_id=str(finding_id) if finding_id else None,
        case_id=str(case_id),
        technique_id=technique_id,
        detail=detail,
    )
