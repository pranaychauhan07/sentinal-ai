"""Case Service — the first orchestrator to compose every subsystem built to
date into blueprint §9's actual data flow: evidence ingestion -> IOC
extraction -> Finding generation -> SOC Analyst Agent analysis, recording a
`TimelineEvent` at each stage.

`core/services` modules calling each other directly (this module calls
`evidence_service.ingest_evidence`, `threat_intel_service.
extract_threat_intelligence`, `finding_service.generate_findings_for_case`)
is normal service composition, not a layering exception —
`docs/dependency-rules.md` has no rule against sibling `core/services`
imports; the documented rules (4a/4b/4c) are specifically about services
reaching *below* `core/graph` into `core/parsers`/`core/threat_intel`/
`core/findings`/`core/memory` directly.

**Rule 4d** (docs/dependency-rules.md, docs/adr/0014-case-model-and-first-api-
routes-shape.md): this module *does* import `core.agents.{registry,
soc_analyst_agent}` and `core.memory.{case_memory,repository}` directly, to
build a session-scoped `SQLiteCaseMemory` and a *fresh* (never the
process-wide cached) `AgentRegistry` before delegating execution to
`core/graph/investigation_graph.py`. This is the one narrow reason: the
cached `default_agent_registry()` singleton would otherwise permanently bake
in whichever caller's `case_memory` (or lack of one) happened to register
`SocAnalystAgent` first. It also imports `core.parsers.models.
{NormalizedEvidence, Severity}` directly for type reuse — the identical
sideways leaf-model precedent `core/db/models/case.py` (and `evidence.py`)
already established, not a new kind of exception.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession

from core.agents.registry import AgentRegistry
from core.agents.soc_analyst_agent import SocAnalystAgent, default_soc_analyst_tool_registry
from core.config import Settings
from core.db.case_repository import CaseRepository
from core.db.models.case import Case, CaseStatus
from core.db.models.timeline_event import TimelineEvent, TimelineEventType
from core.db.timeline_event_repository import TimelineEventRepository
from core.graph.investigation_graph import build_investigation_graph
from core.graph.state import CaseInvestigationState
from core.logging import get_logger, logging_context
from core.memory.case_memory import SQLiteCaseMemory
from core.memory.repository import MemoryRepository
from core.parsers.models import NormalizedEvidence, Severity
from core.services.evidence_service import EvidencePipeline, ingest_evidence
from core.services.finding_service import generate_findings_for_case
from core.services.threat_intel_service import extract_threat_intelligence

_logger = get_logger(__name__)

#: The capability name `SocAnalystAgent` declares — read from the class
#: rather than re-declared as a string literal here, so the two can never
#: silently drift.
_SOC_ANALYST_CAPABILITY = SocAnalystAgent.capabilities[0].name


class CaseInvestigationResult(BaseModel):
    """What `investigate_new_evidence()` returns — the one typed contract a
    caller (a future API route, a test) reads."""

    model_config = ConfigDict(frozen=True)

    case_id: uuid.UUID
    evidence_id: uuid.UUID
    ioc_count: int
    created_finding_ids: tuple[uuid.UUID, ...]
    merged_finding_ids: tuple[uuid.UUID, ...]
    soc_risk_score: float | None = None
    soc_risk_label: str | None = None


async def create_case(
    session: AsyncSession,
    *,
    title: str,
    description: str = "",
    severity: Severity = Severity.INFO,
    analyst_id: str,
) -> Case:
    repository = CaseRepository(session)
    now = datetime.now(UTC)
    case = Case(
        title=title,
        description=description,
        status=CaseStatus.OPEN,
        severity=severity,
        analyst_id=analyst_id,
        created_at=now,
        updated_at=now,
    )
    await repository.add(case)
    await _record_timeline(
        session, case.id, TimelineEventType.CASE_OPENED, f"Case '{title}' opened."
    )
    return case


async def get_case(session: AsyncSession, case_id: uuid.UUID) -> Case | None:
    repository = CaseRepository(session)
    return await repository.get_by_id(case_id)


async def list_cases(
    session: AsyncSession,
    *,
    status: CaseStatus | None = None,
    limit: int = 50,
    cursor: uuid.UUID | None = None,
) -> list[Case]:
    repository = CaseRepository(session)
    if status is not None:
        return await repository.find_by_status(status, limit=limit, cursor=cursor)
    return await repository.list(limit=limit, cursor=cursor)


async def update_case_status(
    session: AsyncSession, case_id: uuid.UUID, status: CaseStatus
) -> Case | None:
    repository = CaseRepository(session)
    case = await repository.update_status(case_id, status)
    if case is not None:
        await _record_timeline(
            session,
            case_id,
            TimelineEventType.CASE_STATUS_CHANGED,
            f"Case status changed to '{status.value}'.",
        )
    return case


async def list_timeline_for_case(
    session: AsyncSession, case_id: uuid.UUID, *, limit: int = 200, cursor: uuid.UUID | None = None
) -> list[TimelineEvent]:
    repository = TimelineEventRepository(session)
    return await repository.find_by_case(case_id, limit=limit, cursor=cursor)


async def _record_timeline(
    session: AsyncSession,
    case_id: uuid.UUID,
    event_type: TimelineEventType,
    narrative: str,
    *,
    source_finding_id: uuid.UUID | None = None,
) -> None:
    repository = TimelineEventRepository(session)
    await repository.add(
        TimelineEvent(
            case_id=case_id,
            timestamp=datetime.now(UTC),
            event_type=event_type,
            source_finding_id=source_finding_id,
            narrative=narrative,
        )
    )


async def _run_soc_analysis(
    session: AsyncSession, *, case_id: uuid.UUID, evidence_items: list[NormalizedEvidence]
) -> CaseInvestigationState:
    """Rule 4d (module docstring): the one place `core/services` constructs
    a session-scoped `CaseMemory` and a fresh `AgentRegistry` before
    delegating to `core/graph`."""
    case_memory = SQLiteCaseMemory(MemoryRepository(session))
    registry = AgentRegistry()
    registry.register(
        SocAnalystAgent(tool_registry=default_soc_analyst_tool_registry(), case_memory=case_memory)
    )
    engine = build_investigation_graph(agent_registry=registry)
    state = CaseInvestigationState(
        case_id=case_id,
        evidence=list(evidence_items),
        metadata={"required_capabilities": [_SOC_ANALYST_CAPABILITY]},
    )
    return engine.run(state)


async def investigate_new_evidence(
    session: AsyncSession,
    *,
    case_id: uuid.UUID,
    filename: str,
    content: bytes,
    settings: Settings,
    ingested_by: str = "unknown",
) -> CaseInvestigationResult:
    """The full blueprint §9 data-flow pipeline for one uploaded artifact:
    ingest -> extract IOCs -> generate Findings -> run SOC analysis,
    recording a `TimelineEvent` at each stage. Composes three already-
    complete, independently-tested pipelines plus this milestone's
    `SocAnalystAgent` run.

    A case moves from `OPEN` to `INVESTIGATING` automatically on its first
    evidence artifact (blueprint §8's lifecycle) — never on later uploads.
    """
    with logging_context(case_id=str(case_id)):
        ingestion = await ingest_evidence(
            session,
            case_id=case_id,
            filename=filename,
            content=content,
            settings=settings,
            pipeline=EvidencePipeline(settings=settings, ingested_by=ingested_by),
        )
        normalized = ingestion.normalized_evidence
        await _record_timeline(
            session,
            case_id,
            TimelineEventType.EVIDENCE_INGESTED,
            f"Evidence '{filename}' ingested: {normalized.record_count} record(s), "
            f"confidence={ingestion.confidence:.2f}.",
        )

        extraction = await extract_threat_intelligence(
            session, case_id=case_id, evidence=normalized, settings=settings
        )
        await _record_timeline(
            session,
            case_id,
            TimelineEventType.IOC_EXTRACTED,
            f"{extraction.ioc_count} IOC(s) extracted from '{filename}'.",
        )

        generation = await generate_findings_for_case(session, case_id=case_id, settings=settings)
        for finding_id in generation.created_finding_ids:
            await _record_timeline(
                session,
                case_id,
                TimelineEventType.FINDING_GENERATED,
                "Finding generated from case IOC(s).",
                source_finding_id=finding_id,
            )

        result_state = await _run_soc_analysis(
            session, case_id=case_id, evidence_items=[normalized]
        )
        soc_risk_score, soc_risk_label = _extract_soc_risk(result_state)
        soc_output = result_state.agent_outputs.get(SocAnalystAgent.name)
        if soc_output is not None:
            await _record_timeline(
                session, case_id, TimelineEventType.AGENT_ANALYSIS, soc_output.thought
            )

        case = await get_case(session, case_id)
        if case is not None and case.status is CaseStatus.OPEN:
            await update_case_status(session, case_id, CaseStatus.INVESTIGATING)

        return CaseInvestigationResult(
            case_id=case_id,
            evidence_id=ingestion.evidence_id,
            ioc_count=extraction.ioc_count,
            created_finding_ids=generation.created_finding_ids,
            merged_finding_ids=generation.merged_finding_ids,
            soc_risk_score=soc_risk_score,
            soc_risk_label=soc_risk_label,
        )


def _extract_soc_risk(state: CaseInvestigationState) -> tuple[float | None, str | None]:
    """Reads the highest risk score/label across this run's `SocFinding`
    payload out of `AgentExecutionResult.output` — the framework layer keeps
    `output` as an opaque dict (`core/agents/contracts.py`), so this is the
    one place `core/services` reaches back into its shape."""
    soc_output = state.agent_outputs.get(SocAnalystAgent.name)
    if soc_output is None:
        return None, None
    findings_payload = soc_output.output.get("findings", [])
    if not findings_payload:
        return None, None
    top = max(findings_payload, key=lambda f: f["risk_score"])
    return top["risk_score"], top["risk_label"]
