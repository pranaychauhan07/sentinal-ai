"""Evidence audit logging — the chain-of-custody trail every ingestion
action leaves, per constitution §8 (structured logging is the
explainability audit trail this product is built around).

Deliberately a thin wrapper over `core.logging`, not a new logging
subsystem: `core/parsers` still ships its own structured events at
`INFO`/`WARNING` from `base.py`/`events.py`; this module exists specifically
for the *evidentiary* record (who uploaded what, when, with which hash) that
a future Report Generator Agent or compliance review would query for, kept
separate so it's trivially greppable/filterable on its own event name.
"""

from __future__ import annotations

import uuid
from enum import StrEnum

from core.logging import get_logger

_logger = get_logger(__name__)


class AuditAction(StrEnum):
    UPLOADED = "uploaded"
    VALIDATED = "validated"
    PARSED = "parsed"
    PERSISTED = "persisted"
    REJECTED = "rejected"


def log_evidence_audit_event(
    *,
    action: AuditAction,
    evidence_id: uuid.UUID | None,
    case_id: uuid.UUID | None,
    actor: str,
    filename: str,
    sha256: str | None = None,
    detail: str = "",
) -> None:
    """Emit one structured, queryable audit log line. Never raises — an
    audit-logging failure must not abort evidence ingestion (constitution
    §9's degraded-not-fatal rule); a failure here is caught and logged as a
    warning by the caller's own structured logger instead of propagating.
    """
    _logger.info(
        "evidence_audit_event",
        action=action.value,
        evidence_id=str(evidence_id) if evidence_id else None,
        case_id=str(case_id) if case_id else None,
        actor=actor,
        filename=filename,
        sha256=sha256,
        detail=detail,
    )
