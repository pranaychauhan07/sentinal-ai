"""`ReportRepository` — the sanctioned place raw SQLAlchemy queries against
`Report` live (constitution §7), mirroring
`core.db.incident_response_plan_repository.IncidentResponsePlanRepository`'s
shape. `upsert_for_case` is this repository's one non-generic method — the
"1 nullable per case" cardinality (docs/adr/0024 Decision 4) means every
write replaces, never appends.

`upsert_for_case` takes the report as a plain `dict[str, object]` (the same
shape `AgentExecutionResult.output["report"]` already carries —
`GeneratedReport.model_dump(mode="json")`'d by
`core/agents/report_generator_agent.py`), not a typed
`core.reporting.models.GeneratedReport` — this is what lets
`core/services/case_service.py` call it without a new dependency-rules.md
import edge onto `core/reporting` (that package's Pydantic model stays
imported only here, in `core/db`, which already imports leaf-package model
types for column typing — see `core/db/models/report.py`'s docstring).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.db.base_repository import BaseRepository
from core.db.models.report import Report
from core.reporting.models import GeneratedReport


class ReportRepository(BaseRepository[Report]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, Report)

    async def find_by_case(self, case_id: uuid.UUID) -> Report | None:
        stmt = select(Report).where(Report.case_id == case_id)
        result = await self._session.execute(stmt)
        return result.scalars().first()

    async def upsert_for_case(self, case_id: uuid.UUID, report_data: dict[str, Any]) -> Report:
        """Replaces this case's existing report row (if any) with
        `report_data`, never appending a second row for the same case
        (blueprint §8's literal "1 nullable" cardinality)."""
        report = GeneratedReport.model_validate(report_data)
        now = datetime.now(UTC)
        existing = await self.find_by_case(case_id)
        report_data_json = report.model_dump_json()
        if existing is not None:
            existing.report_type = report.report_type
            existing.title = report.title
            existing.report_data_json = report_data_json
            existing.overall_confidence = report.confidence
            existing.degraded = report.degraded
            existing.generated_at = now
            await self._session.flush()
            return existing

        row = Report(
            case_id=case_id,
            report_type=report.report_type,
            title=report.title,
            report_data_json=report_data_json,
            overall_confidence=report.confidence,
            degraded=report.degraded,
            generated_at=now,
        )
        return await self.add(row)
