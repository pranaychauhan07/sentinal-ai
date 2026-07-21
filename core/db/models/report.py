"""`Report` — blueprint §8's schema-only placeholder for this milestone,
extended this session (`docs/adr/0024-report-generator-agent.md`, Decision
4) to actually persist a generated report: `ReportGeneratorAgent` upserts
one row per case via `core.db.report_repository.ReportRepository.
upsert_for_case`, mirroring `IncidentResponsePlanRow`'s identical "1
nullable per case" cardinality (blueprint §8: `Case ├─ ... └─ 1 Report`).

`file_path`/`generated_at` stay real, additive columns from this table's
original (M0-era) definition: `generated_at` is now populated (a report
genuinely is generated), but `file_path` stays `NULL` until a future session
adds a concrete PDF/HTML/Markdown exporter (task instruction this session:
"implement only the backend models and generation pipeline... do not build
exporters yet") — no report is ever exported to a file yet.

`ReportType` is no longer this module's own enum — it is now re-exported
from `core.reporting.models.ReportType`, the leaf package that owns the
*domain* concept, imported here for column typing only (the identical "DB
imports a sibling leaf's model" precedent `core/db/models/finding.py`
(`core.findings.models.FindingSeverity`) and `core/db/models/
incident_response_plan.py` (`core.incident_response.models.IncidentSeverity`)
already set). Its two original values (`module`, `executive`) are unchanged;
six new values were added additively.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Index, String, Text
from sqlalchemy import Enum as SqlEnum
from sqlalchemy.orm import Mapped, mapped_column

from core.db.session import Entity
from core.reporting.models import ReportType

__all__ = ["Report", "ReportType"]


class Report(Entity):
    __tablename__ = "reports"
    __table_args__ = (
        Index("ix_reports_case_id", "case_id", unique=True),
        Index("ix_reports_report_type", "report_type"),
    )

    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )
    report_type: Mapped[ReportType] = mapped_column(
        SqlEnum(
            ReportType, name="report_type_enum", values_callable=lambda e: [x.value for x in e]
        ),
        nullable=False,
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    #: The full serialized `core.reporting.models.GeneratedReport` — the
    #: same "denormalized columns + one full JSON blob" shape
    #: `IncidentResponsePlanRow.plan_data_json` already established.
    report_data_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    overall_confidence: Mapped[float] = mapped_column(nullable=False, default=0.0)
    degraded: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    generated_at: Mapped[datetime | None] = mapped_column(nullable=True)
