"""`IncidentResponsePlanRow` — blueprint §8's schema-named
`Case ├─ 1 IncidentResponsePlan (nullable)`, arriving with the Incident
Response Agent (docs/adr/0023-incident-response-agent.md, Decision 3).

Named `IncidentResponsePlanRow` (not `IncidentResponsePlan`) to avoid a
same-name collision with the Pydantic model this ORM row persists —
mirroring `core.db.models.linux_security_finding.LinuxSecurityFindingRow`'s
identical "Row" suffix precedent (constitution §7: ORM rows are the
persistence representation; Pydantic models are what every other layer
works with).

One row per `case_id` (a real unique constraint, not just convention) —
regenerating a case's plan **replaces** the existing row rather than
appending a new one, matching blueprint's literal "1 nullable" cardinality
(distinct from `Finding`, where a case legitimately accumulates many rows).
`plan_data_json` is the full serialized
`core.incident_response.models.IncidentResponsePlan` (every recommendation,
its evidence, its MITRE references, the plan's metrics) — the small
denormalized columns below (`incident_severity`, `overall_risk_score`,
`overall_confidence`, `plan_degraded`) exist only for indexed list/filter
queries, mirroring `Finding.severity`/`Finding.risk_score`'s identical
"denormalized column + full JSON blob" precedent.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Index, Text
from sqlalchemy import Enum as SqlEnum
from sqlalchemy.orm import Mapped, mapped_column

from core.db.session import Entity
from core.incident_response.models import IncidentSeverity


class IncidentResponsePlanRow(Entity):
    __tablename__ = "incident_response_plans"
    __table_args__ = (
        Index("ix_incident_response_plans_case_id", "case_id", unique=True),
        Index("ix_incident_response_plans_incident_severity", "incident_severity"),
    )

    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )
    incident_severity: Mapped[IncidentSeverity] = mapped_column(
        SqlEnum(
            IncidentSeverity,
            name="incident_response_severity_enum",
            values_callable=lambda enum: [e.value for e in enum],
        ),
        nullable=False,
    )
    overall_risk_score: Mapped[float] = mapped_column(nullable=False, default=0.0)
    overall_confidence: Mapped[float] = mapped_column(nullable=False, default=0.0)
    plan_degraded: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    plan_data_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(nullable=False)
    updated_at: Mapped[datetime] = mapped_column(nullable=False)
