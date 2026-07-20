"""Linux Security Analysis Framework audit logging — the evidentiary/
attribution trail every detection action leaves, mirroring
`core.vulnerabilities.audit`'s "thin wrapper over `core.logging`" pattern
exactly.
"""

from __future__ import annotations

import uuid
from enum import StrEnum

from core.logging import get_logger

_logger = get_logger(__name__)


class AuditAction(StrEnum):
    NORMALIZED = "normalized"
    DETECTED = "detected"
    SCORED = "scored"
    FINDING_GENERATED = "finding_generated"
    PERSISTED = "persisted"
    REJECTED = "rejected"


def log_linux_security_audit_event(
    *,
    action: AuditAction,
    finding_id: uuid.UUID | None,
    evidence_id: uuid.UUID | None,
    case_id: uuid.UUID | None,
    category: str | None = None,
    detail: str = "",
) -> None:
    """Emit one structured, queryable audit log line. Never raises — an
    audit-logging failure must not abort analysis (constitution §9's
    degraded-not-fatal rule), matching
    `core.vulnerabilities.audit.log_vulnerability_audit_event`'s contract."""
    _logger.info(
        "linux_security_audit_event",
        action=action.value,
        finding_id=str(finding_id) if finding_id else None,
        evidence_id=str(evidence_id) if evidence_id else None,
        case_id=str(case_id) if case_id else None,
        category=category,
        detail=detail,
    )
