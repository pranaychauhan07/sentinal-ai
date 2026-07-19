"""`Case` — the blueprint's central object (blueprint §1, §8), arriving with
Milestone M1. Every other domain table's `case_id` (`Evidence`, `IOC`,
`Finding`) was deliberately left a plain UUID column pending this model
(ADR-0011 point of precedent, restated in ADR-0012/0013); a follow-up,
purely-additive migration in this same change tightens all three into real
foreign keys (constitution §7, "Future scalability").

ADR-0015 extends this model additively: five new `CaseStatus` values
(escalated/on_hold/contained/resolved/archived — the original three are
never renamed, constitution §13), `CasePriority`, `owner_id`/`assignee_id`
(placeholder string columns matching `analyst_id`'s existing shape),
`risk_score` (a case-level rollup computed by
`core/services/case_metrics.py`, never written directly), and `labels`
(freeform, unindexed JSON metadata — distinct from the indexed `case_tags`
join table in `core/db/models/case_tag.py`).
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from sqlalchemy import Enum as SqlEnum
from sqlalchemy import Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from core.db.session import Entity
from core.parsers.models import Severity


class CaseStatus(StrEnum):
    """Case lifecycle (blueprint §8: "status (open/investigating/closed)").

    ADR-0015 extends this additively with five escalation-capable states;
    `OPEN`/`INVESTIGATING`/`CLOSED` are the original, unchanged, persisted
    values. `core/services/case_lifecycle.py` owns which transitions between
    all eight values are legal."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    CLOSED = "closed"
    ESCALATED = "escalated"
    ON_HOLD = "on_hold"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    ARCHIVED = "archived"


class CasePriority(StrEnum):
    """Analyst triage priority (ADR-0015) — distinct from `severity`, matching
    `core.findings.models.FindingPriority`'s "priority is a triage ordering,
    severity is an impact assessment" separation of concerns."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Case(Entity):
    """One investigation. Everything else in the system (`Evidence`, `IOC`,
    `Finding`, `TimelineEvent`, `Report`) hangs off a `case_id`."""

    __tablename__ = "cases"
    __table_args__ = (
        Index("ix_cases_status", "status"),
        Index("ix_cases_severity", "severity"),
        Index("ix_cases_analyst_id", "analyst_id"),
    )

    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status: Mapped[CaseStatus] = mapped_column(
        SqlEnum(
            CaseStatus, name="case_status_enum", values_callable=lambda e: [x.value for x in e]
        ),
        nullable=False,
        default=CaseStatus.OPEN,
    )
    #: Reused, not re-declared — the same closed severity scale every
    #: parser record already carries (constitution §14.9, "never duplicate").
    severity: Mapped[Severity] = mapped_column(
        SqlEnum(
            Severity, name="case_severity_enum", values_callable=lambda e: [x.value for x in e]
        ),
        nullable=False,
        default=Severity.INFO,
    )
    #: Single-analyst mode (blueprint §3) — matches
    #: `apps.api.dependencies.AuthenticatedUser.id`'s placeholder shape;
    #: becomes a real FK once a `User` table exists (blueprint §17).
    analyst_id: Mapped[str] = mapped_column(String(255), nullable=False)
    priority: Mapped[CasePriority] = mapped_column(
        SqlEnum(
            CasePriority, name="case_priority_enum", values_callable=lambda e: [x.value for x in e]
        ),
        nullable=False,
        default=CasePriority.MEDIUM,
    )
    #: Rollup of this case's open `Finding.risk_score` values, computed by
    #: `core/services/case_metrics.py::compute_case_risk_score` — never
    #: written directly by a router/agent (ADR-0015 point 3).
    risk_score: Mapped[float | None] = mapped_column(nullable=True)
    #: Placeholder string columns, same shape as `analyst_id` (ADR-0015
    #: point 4) — `owner_id` is the accountable analyst, `assignee_id` is
    #: who is actively working the case now.
    owner_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    assignee_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    #: Freeform key->value metadata, serialized JSON, intentionally
    #: unindexed and unqueryable — distinct from the indexed `case_tags`
    #: join table (ADR-0015 point 6).
    labels: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(nullable=False)
    updated_at: Mapped[datetime] = mapped_column(nullable=False)
    closed_at: Mapped[datetime | None] = mapped_column(nullable=True)
