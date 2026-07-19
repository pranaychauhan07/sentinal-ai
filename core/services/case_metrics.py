"""Case-level metrics/observability (ADR-0015 points 3 and 7) — mirroring
`core.findings.metrics.FindingsMetricsCollector`'s shape exactly.

`compute_case_risk_score` is the one function with a database dependency
(it reads persisted `Finding` rows via `core.db.finding_repository.
FindingRepository`, a normal `core/db` repository call every `core/services`
module already makes — no new dependency-rules exception, ADR-0015 point 8).
It aggregates `Finding.risk_score` values the Finding & MITRE Engine
(ADR-0013) already computed and persisted; it never re-derives severity/risk
math itself, matching ADR-0014 point 5's "one source of truth per score
type" discipline.
"""

from __future__ import annotations

import uuid

from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from core.db.finding_repository import FindingRepository
from core.db.models.case import CasePriority, CaseStatus


class CaseMetricsSnapshot(BaseModel):
    """Point-in-time export of case-lifecycle counters."""

    by_status: dict[str, int] = Field(default_factory=dict)
    by_priority: dict[str, int] = Field(default_factory=dict)
    escalations: int = 0
    resolutions: int = 0
    total_resolution_seconds: float = 0.0

    @property
    def escalation_rate(self) -> float:
        total = sum(self.by_status.values())
        if total == 0:
            return 0.0
        return self.escalations / total

    @property
    def average_resolution_seconds(self) -> float:
        if self.resolutions == 0:
            return 0.0
        return self.total_resolution_seconds / self.resolutions


class CaseMetricsCollector:
    """Construct one per process (or one per test for isolation) — matches
    `core.findings.metrics.FindingsMetricsCollector`'s convention."""

    def __init__(self) -> None:
        self._by_status: dict[str, int] = {}
        self._by_priority: dict[str, int] = {}
        self._escalations = 0
        self._resolutions = 0
        self._total_resolution_seconds = 0.0

    def record_case_created(self, priority: CasePriority) -> None:
        self._by_status[CaseStatus.OPEN.value] = self._by_status.get(CaseStatus.OPEN.value, 0) + 1
        self._by_priority[priority.value] = self._by_priority.get(priority.value, 0) + 1

    def record_status_change(self, previous: CaseStatus, new: CaseStatus) -> None:
        self._by_status[previous.value] = max(0, self._by_status.get(previous.value, 0) - 1)
        self._by_status[new.value] = self._by_status.get(new.value, 0) + 1
        if new is CaseStatus.ESCALATED:
            self._escalations += 1

    def record_resolution(self, duration_seconds: float) -> None:
        self._resolutions += 1
        self._total_resolution_seconds += duration_seconds

    def snapshot(self) -> CaseMetricsSnapshot:
        return CaseMetricsSnapshot(
            by_status=dict(self._by_status),
            by_priority=dict(self._by_priority),
            escalations=self._escalations,
            resolutions=self._resolutions,
            total_resolution_seconds=self._total_resolution_seconds,
        )


async def compute_case_risk_score(session: AsyncSession, case_id: uuid.UUID) -> float | None:
    """The case-level risk-score rollup (ADR-0015 point 3): the maximum
    `Finding.risk_score` among the case's currently-open Findings — an
    analyst triages by worst-open-finding, the same reasoning
    `core.services.case_service._extract_soc_risk` already applies to
    `SocFinding`s. Returns ``None`` if the case has no open Findings yet
    (distinct from a real ``0.0`` risk score)."""
    repository = FindingRepository(session)
    open_findings = await repository.find_open_for_case(case_id)
    if not open_findings:
        return None
    return max(finding.risk_score for finding in open_findings)
