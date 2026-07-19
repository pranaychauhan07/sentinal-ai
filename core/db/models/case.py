"""`Case` — the blueprint's central object (blueprint §1, §8), arriving with
Milestone M1. Every other domain table's `case_id` (`Evidence`, `IOC`,
`Finding`) was deliberately left a plain UUID column pending this model
(ADR-0011 point of precedent, restated in ADR-0012/0013); a follow-up,
purely-additive migration in this same change tightens all three into real
foreign keys (constitution §7, "Future scalability").
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
    """Case lifecycle (blueprint §8: "status (open/investigating/closed)")."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    CLOSED = "closed"


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
    created_at: Mapped[datetime] = mapped_column(nullable=False)
    updated_at: Mapped[datetime] = mapped_column(nullable=False)
    closed_at: Mapped[datetime | None] = mapped_column(nullable=True)
