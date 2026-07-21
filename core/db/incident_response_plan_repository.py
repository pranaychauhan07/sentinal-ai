"""`IncidentResponsePlanRepository` — the sanctioned place raw SQLAlchemy
queries against `IncidentResponsePlanRow` live (constitution §7), mirroring
`core.db.linux_security_finding_repository.LinuxSecurityFindingRepository`'s
shape. `upsert_for_case` is this repository's one non-generic method — the
"1 nullable per case" cardinality (docs/adr/0023 Decision 3) means every
write replaces, never appends.

`upsert_for_case` takes the plan as a plain `dict[str, object]` (the same
shape `AgentExecutionResult.output["plan"]` already carries —
`IncidentResponsePlan.model_dump(mode="json")`'d by
`core/agents/incident_response_agent.py`), not a typed
`core.incident_response.models.IncidentResponsePlan` — this is what lets
`core/services/case_service.py` call it without a new dependency-rules.md
import edge onto `core/incident_response` (that package's Pydantic model
stays imported only here, in `core/db`, which already imports
leaf-package model types for column typing — the same precedent
`core/db/models/finding.py` importing `core.findings.models.FindingSeverity`
already set)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.db.base_repository import BaseRepository
from core.db.models.incident_response_plan import IncidentResponsePlanRow
from core.incident_response.models import IncidentResponsePlan


class IncidentResponsePlanRepository(BaseRepository[IncidentResponsePlanRow]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(session, IncidentResponsePlanRow)

    async def find_by_case(self, case_id: uuid.UUID) -> IncidentResponsePlanRow | None:
        stmt = select(IncidentResponsePlanRow).where(IncidentResponsePlanRow.case_id == case_id)
        result = await self._session.execute(stmt)
        return result.scalars().first()

    async def upsert_for_case(
        self, case_id: uuid.UUID, plan_data: dict[str, Any]
    ) -> IncidentResponsePlanRow:
        """Replaces this case's existing plan row (if any) with `plan_data`,
        never appending a second row for the same case (blueprint §8's
        literal "1 nullable" cardinality)."""
        plan = IncidentResponsePlan.model_validate(plan_data)
        now = datetime.now(UTC)
        existing = await self.find_by_case(case_id)
        plan_data_json = plan.model_dump_json()
        if existing is not None:
            existing.incident_severity = plan.incident_severity
            existing.overall_risk_score = plan.overall_risk_score
            existing.overall_confidence = plan.overall_confidence
            existing.plan_degraded = plan.plan_degraded
            existing.plan_data_json = plan_data_json
            existing.updated_at = now
            await self._session.flush()
            return existing

        row = IncidentResponsePlanRow(
            case_id=case_id,
            incident_severity=plan.incident_severity,
            overall_risk_score=plan.overall_risk_score,
            overall_confidence=plan.overall_confidence,
            plan_degraded=plan.plan_degraded,
            plan_data_json=plan_data_json,
            created_at=now,
            updated_at=now,
        )
        return await self.add(row)
