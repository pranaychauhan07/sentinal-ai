"""Vulnerability Assessment Framework audit logging — the evidentiary/
attribution trail every vulnerability-processing action leaves, mirroring
`core.threat_intel.audit`'s "thin wrapper over `core.logging`" pattern
exactly. Kept separate from `core.vulnerabilities.events` for the same
reason: this is the evidentiary record (what vulnerability, from which
evidence, scored how), trivially greppable/filterable on its own event
name, distinct from the pub-sub lifecycle-notification concern.
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
    SCORED = "scored"
    FINDING_GENERATED = "finding_generated"
    PERSISTED = "persisted"
    REJECTED = "rejected"


def log_vulnerability_audit_event(
    *,
    action: AuditAction,
    vuln_id: uuid.UUID | None,
    evidence_id: uuid.UUID | None,
    case_id: uuid.UUID | None,
    cve_id: str | None = None,
    detail: str = "",
) -> None:
    """Emit one structured, queryable audit log line. Never raises — an
    audit-logging failure must not abort vulnerability processing
    (constitution §9's degraded-not-fatal rule), matching
    `core.threat_intel.audit.log_threat_intel_audit_event`'s contract."""
    _logger.info(
        "vulnerability_audit_event",
        action=action.value,
        vuln_id=str(vuln_id) if vuln_id else None,
        evidence_id=str(evidence_id) if evidence_id else None,
        case_id=str(case_id) if case_id else None,
        cve_id=cve_id,
        detail=detail,
    )
