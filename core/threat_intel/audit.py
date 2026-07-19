"""Threat intelligence audit logging — the evidentiary/attribution trail
every IOC extraction action leaves, mirroring `core.parsers.audit`'s
"thin wrapper over `core.logging`" pattern exactly, kept separate from
`core.threat_intel.events` for the same reason `core/parsers/audit.py` is
kept separate from `core/parsers/events.py`: this is the evidentiary record
(what IOC, from which evidence, classified how), trivially greppable/
filterable on its own event name.
"""

from __future__ import annotations

import uuid
from enum import StrEnum

from core.logging import get_logger

_logger = get_logger(__name__)


class AuditAction(StrEnum):
    EXTRACTED = "extracted"
    VALIDATED = "validated"
    NORMALIZED = "normalized"
    DEDUPLICATED = "deduplicated"
    CLASSIFIED = "classified"
    SCORED = "scored"
    PERSISTED = "persisted"
    REJECTED = "rejected"


def log_threat_intel_audit_event(
    *,
    action: AuditAction,
    ioc_id: uuid.UUID | None,
    evidence_id: uuid.UUID | None,
    case_id: uuid.UUID | None,
    ioc_type: str | None = None,
    detail: str = "",
) -> None:
    """Emit one structured, queryable audit log line. Never raises — an
    audit-logging failure must not abort IOC extraction (constitution §9's
    degraded-not-fatal rule), matching `core.parsers.audit.
    log_evidence_audit_event`'s contract."""
    _logger.info(
        "threat_intel_audit_event",
        action=action.value,
        ioc_id=str(ioc_id) if ioc_id else None,
        evidence_id=str(evidence_id) if evidence_id else None,
        case_id=str(case_id) if case_id else None,
        ioc_type=ioc_type,
        detail=detail,
    )
