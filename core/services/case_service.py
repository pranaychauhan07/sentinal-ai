"""Case Service — the first orchestrator to compose every subsystem built to
date into blueprint §9's actual data flow: evidence ingestion -> IOC
extraction -> Finding generation -> SOC Analyst Agent analysis, recording a
`TimelineEvent` at each stage.

ADR-0015 extends this module additively: case ownership/priority/tags/notes
mutation functions, lifecycle-transition validation on `update_case_status`
(delegating to `core.services.case_lifecycle.validate_transition` before
`CaseRepository.update_status` is ever called — never inside the repository
itself, since `core/db` cannot import `core/services`), `CaseEvent`
publication alongside every existing `TimelineEvent` recording, and
case-level risk-score recomputation (`core.services.case_metrics`). No
existing function's contract changes except `update_case_status`, which now
raises `BusinessRuleError` on an illegal transition instead of unconditionally
succeeding (ADR-0015 "Consequences").

`core/services` modules calling each other directly (this module calls
`evidence_service.ingest_evidence`, `threat_intel_service.
extract_threat_intelligence`, `finding_service.generate_findings_for_case`)
is normal service composition, not a layering exception —
`docs/dependency-rules.md` has no rule against sibling `core/services`
imports; the documented rules (4a/4b/4c) are specifically about services
reaching *below* `core/graph` into `core/parsers`/`core/threat_intel`/
`core/findings`/`core/memory` directly.

**Rule 4d** (docs/dependency-rules.md, docs/adr/0014-case-model-and-first-api-
routes-shape.md, extended by docs/adr/0016-phishing-agent-email-parser-
prompt-guard.md): this module *does* import `core.agents.{registry,
soc_analyst_agent, phishing_agent}` and `core.memory.{case_memory,repository}`
directly, to build a session-scoped `SQLiteCaseMemory` and a *fresh* (never
the process-wide cached) `AgentRegistry` before delegating execution to
`core/graph/investigation_graph.py`. This is the one narrow reason: the
cached `default_agent_registry()` singleton would otherwise permanently bake
in whichever caller's `case_memory` (or lack of one) happened to register
`SocAnalystAgent`/`PhishingAgent` first. It also imports `core.parsers.models.
{EvidenceType, NormalizedEvidence, Severity}` directly for type reuse — the
identical sideways leaf-model precedent `core/db/models/case.py` (and
`evidence.py`) already established, not a new kind of exception. Reading
`core.db.ioc_repository.IOCRepository` needs no new exception at all: every
other `core/db` repository (`CaseRepository`, `CaseNoteRepository`, ...) is
already imported directly here — `core/services` -> `core/db` is a normal,
always-sanctioned edge (constitution §7), distinct from the 4a/4b/4c
exceptions that are specifically about reaching into the deterministic leaf
*processing* packages (`core/parsers`/`core/threat_intel`/`core/findings`).
`PhishingAgent` needs its case's already-persisted, already-scored IOCs
(`IOC.composite_score`) reduced to plain dicts before they're hydrated onto
`CaseInvestigationState.extracted_indicators` — see `_hydrate_attributed_iocs`
below and `core/agents/phishing_agent.py`'s docstring for why this stays
string/dict-typed rather than a `core.threat_intel.models.ScoredIOC` import.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession

from core.agents.phishing_agent import PhishingAgent, default_phishing_agent_tool_registry
from core.agents.registry import AgentRegistry
from core.agents.soc_analyst_agent import SocAnalystAgent, default_soc_analyst_tool_registry
from core.config import Settings
from core.db.case_note_repository import CaseNoteRepository
from core.db.case_repository import CaseRepository
from core.db.case_tag_repository import CaseTagRepository
from core.db.ioc_repository import IOCRepository
from core.db.models.case import Case, CasePriority, CaseStatus
from core.db.models.case_note import CaseNote
from core.db.models.case_tag import CaseTag
from core.db.models.timeline_event import TimelineEvent, TimelineEventType
from core.db.timeline_event_repository import TimelineEventRepository
from core.exceptions import BusinessRuleError
from core.graph.investigation_graph import build_investigation_graph
from core.graph.state import CaseInvestigationState
from core.logging import get_logger, logging_context
from core.memory.case_memory import SQLiteCaseMemory
from core.memory.repository import MemoryRepository
from core.parsers.models import EvidenceType, NormalizedEvidence, Severity
from core.services.case_events import CaseEvent, CaseEventPublisher, CaseEventType
from core.services.case_lifecycle import validate_transition
from core.services.case_metrics import compute_case_risk_score
from core.services.evidence_service import EvidencePipeline, ingest_evidence
from core.services.finding_service import generate_findings_for_case
from core.services.threat_intel_service import extract_threat_intelligence

_logger = get_logger(__name__)

#: `CaseStatus` values that map to a specific `CaseEventType` on transition;
#: every other target status publishes the generic `CASE_UPDATED` event.
_STATUS_TO_EVENT_TYPE: dict[CaseStatus, CaseEventType] = {
    CaseStatus.ESCALATED: CaseEventType.CASE_ESCALATED,
    CaseStatus.RESOLVED: CaseEventType.CASE_RESOLVED,
    CaseStatus.CLOSED: CaseEventType.CASE_CLOSED,
}

#: The capability names `SocAnalystAgent`/`PhishingAgent` declare — read from
#: the classes rather than re-declared as string literals here, so these can
#: never silently drift.
_SOC_ANALYST_CAPABILITY = SocAnalystAgent.capabilities[0].name
_PHISHING_CAPABILITY = PhishingAgent.capabilities[0].name

#: Which capability a newly-ingested artifact's `EvidenceType` requires —
#: the per-upload routing decision that lets the Coordinator fan out to the
#: right specialist(s) automatically (blueprint §7's Coordinator/Planning
#: Agent responsibility, closing M3's own demo criterion:
#: "upload mixed evidence to one Case and watch the Coordinator fan out to
#: both agents automatically"). Additive: any `EvidenceType` not listed here
#: falls back to `_SOC_ANALYST_CAPABILITY`, matching the pre-M2 behavior for
#: every log-shaped format this framework already parses.
_EVIDENCE_TYPE_CAPABILITY: dict[EvidenceType, str] = {
    EvidenceType.EMAIL: _PHISHING_CAPABILITY,
}


def _required_capability_for(evidence_type: EvidenceType) -> str:
    return _EVIDENCE_TYPE_CAPABILITY.get(evidence_type, _SOC_ANALYST_CAPABILITY)


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
    phishing_risk_score: float | None = None
    phishing_risk_label: str | None = None


async def create_case(
    session: AsyncSession,
    *,
    title: str,
    description: str = "",
    severity: Severity = Severity.INFO,
    priority: CasePriority = CasePriority.MEDIUM,
    analyst_id: str,
    event_publisher: CaseEventPublisher | None = None,
) -> Case:
    """Create a case. Rejects an exact `(title, analyst_id)` duplicate
    against a still-active case (ADR-0015 point 10) — a narrow, cheap guard,
    not semantic/fuzzy dedup (that's `core/memory`'s advisory-only job)."""
    repository = CaseRepository(session)
    duplicate = await repository.find_open_by_title_and_analyst(title, analyst_id)
    if duplicate is not None:
        raise BusinessRuleError(
            f"An active case titled '{title}' already exists for analyst '{analyst_id}'.",
            details={"existing_case_id": str(duplicate.id), "title": title},
        )

    now = datetime.now(UTC)
    case = Case(
        title=title,
        description=description,
        status=CaseStatus.OPEN,
        severity=severity,
        priority=priority,
        analyst_id=analyst_id,
        owner_id=analyst_id,
        created_at=now,
        updated_at=now,
    )
    await repository.add(case)
    await _record_timeline(
        session, case.id, TimelineEventType.CASE_OPENED, f"Case '{title}' opened."
    )
    (event_publisher or CaseEventPublisher()).publish(
        CaseEvent(event_type=CaseEventType.CASE_CREATED, case_id=case.id, detail=title)
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
    session: AsyncSession,
    case_id: uuid.UUID,
    status: CaseStatus,
    *,
    event_publisher: CaseEventPublisher | None = None,
) -> Case | None:
    """Move a case to ``status``, validated against
    `core.services.case_lifecycle.validate_transition` *before*
    `CaseRepository.update_status` is called (ADR-0015 point 9) — raises
    `BusinessRuleError` on an illegal transition (e.g. `ARCHIVED -> OPEN`)."""
    repository = CaseRepository(session)
    existing = await repository.get_by_id(case_id)
    if existing is None:
        return None
    validate_transition(existing.status, status)

    case = await repository.update_status(case_id, status)
    if case is not None:
        await _record_timeline(
            session,
            case_id,
            TimelineEventType.CASE_STATUS_CHANGED,
            f"Case status changed to '{status.value}'.",
        )
        event_type = _STATUS_TO_EVENT_TYPE.get(status, CaseEventType.CASE_UPDATED)
        (event_publisher or CaseEventPublisher()).publish(
            CaseEvent(event_type=event_type, case_id=case_id, detail=status.value)
        )
    return case


async def update_case_assignment(
    session: AsyncSession,
    case_id: uuid.UUID,
    *,
    owner_id: str | None = None,
    assignee_id: str | None = None,
    event_publisher: CaseEventPublisher | None = None,
) -> Case | None:
    """Update `Case.owner_id`/`Case.assignee_id` (ADR-0015 point 4). Either
    argument left `None` leaves that field unchanged."""
    repository = CaseRepository(session)
    case = await repository.update_ownership(case_id, owner_id=owner_id, assignee_id=assignee_id)
    if case is not None:
        await _record_timeline(
            session,
            case_id,
            TimelineEventType.CASE_ASSIGNED,
            f"Case assignment updated (owner='{case.owner_id}', assignee='{case.assignee_id}').",
        )
        (event_publisher or CaseEventPublisher()).publish(
            CaseEvent(event_type=CaseEventType.CASE_ASSIGNED, case_id=case_id)
        )
    return case


async def update_case_details(
    session: AsyncSession,
    case_id: uuid.UUID,
    *,
    title: str | None = None,
    description: str | None = None,
    event_publisher: CaseEventPublisher | None = None,
) -> Case | None:
    """Partial update of `Case.title`/`Case.description`. Either argument
    left `None` leaves that field unchanged — matches
    `update_case_assignment`'s shape."""
    repository = CaseRepository(session)
    case = await repository.get_by_id(case_id)
    if case is None:
        return None
    if title is not None:
        case.title = title
    if description is not None:
        case.description = description
    case.updated_at = datetime.now(UTC)
    await session.flush()
    (event_publisher or CaseEventPublisher()).publish(
        CaseEvent(event_type=CaseEventType.CASE_UPDATED, case_id=case_id)
    )
    return case


async def update_case_priority(
    session: AsyncSession,
    case_id: uuid.UUID,
    priority: CasePriority,
    *,
    event_publisher: CaseEventPublisher | None = None,
) -> Case | None:
    repository = CaseRepository(session)
    case = await repository.update_priority(case_id, priority)
    if case is not None:
        (event_publisher or CaseEventPublisher()).publish(
            CaseEvent(
                event_type=CaseEventType.CASE_UPDATED,
                case_id=case_id,
                detail=f"priority={priority.value}",
            )
        )
    return case


async def update_case_labels(
    session: AsyncSession,
    case_id: uuid.UUID,
    labels: dict[str, str],
    *,
    event_publisher: CaseEventPublisher | None = None,
) -> Case | None:
    """Replace `Case.labels` (ADR-0015 point 6: freeform, unindexed
    key->value metadata — distinct from the filterable `case_tags` table).
    Serialization to JSON happens here, one layer above `core/db`, matching
    the `Evidence.parsed_json`/`Finding.finding_data_json` precedent."""
    repository = CaseRepository(session)
    case = await repository.update_labels_json(case_id, json.dumps(labels))
    if case is not None:
        (event_publisher or CaseEventPublisher()).publish(
            CaseEvent(event_type=CaseEventType.CASE_UPDATED, case_id=case_id, detail="labels")
        )
    return case


async def recompute_case_risk_score(session: AsyncSession, case_id: uuid.UUID) -> float | None:
    """Recompute and persist `Case.risk_score` from currently-open Findings
    (`core.services.case_metrics.compute_case_risk_score`). Returns `None`
    without writing anything if the case has no open Findings yet."""
    risk_score = await compute_case_risk_score(session, case_id)
    if risk_score is not None:
        repository = CaseRepository(session)
        await repository.update_risk_score(case_id, risk_score)
    return risk_score


async def add_case_note(
    session: AsyncSession, case_id: uuid.UUID, *, author_id: str, body: str
) -> CaseNote:
    """Create an editable `CaseNote` (ADR-0015 point 2), recording a paired,
    immutable `TimelineEvent(MANUAL_NOTE)` so the audit trail always
    reflects that a note was added, by whom."""
    repository = CaseNoteRepository(session)
    now = datetime.now(UTC)
    note = await repository.add(
        CaseNote(case_id=case_id, author_id=author_id, body=body, created_at=now, updated_at=now)
    )
    await _record_timeline(
        session, case_id, TimelineEventType.MANUAL_NOTE, f"Note added by '{author_id}'."
    )
    return note


async def update_case_note(
    session: AsyncSession, note_id: uuid.UUID, *, body: str
) -> CaseNote | None:
    """Edit an existing `CaseNote`'s body, recording a paired
    `TimelineEvent(MANUAL_NOTE)` (ADR-0015 point 2)."""
    repository = CaseNoteRepository(session)
    note = await repository.update_body(note_id, body)
    if note is not None:
        await _record_timeline(
            session, note.case_id, TimelineEventType.MANUAL_NOTE, "Note updated."
        )
    return note


async def delete_case_note(session: AsyncSession, note_id: uuid.UUID) -> bool:
    """Delete a `CaseNote`, recording a paired `TimelineEvent(MANUAL_NOTE)`
    (ADR-0015 point 2) before the row is gone so the audit trail still
    reflects it. Returns `False` if the note did not exist."""
    repository = CaseNoteRepository(session)
    existing = await repository.get_by_id(note_id)
    if existing is None:
        return False
    case_id = existing.case_id
    await repository.delete(note_id)
    await _record_timeline(session, case_id, TimelineEventType.MANUAL_NOTE, "Note deleted.")
    return True


async def get_case_note(session: AsyncSession, note_id: uuid.UUID) -> CaseNote | None:
    repository = CaseNoteRepository(session)
    return await repository.get_by_id(note_id)


async def list_case_notes(
    session: AsyncSession, case_id: uuid.UUID, *, limit: int = 200, cursor: uuid.UUID | None = None
) -> list[CaseNote]:
    repository = CaseNoteRepository(session)
    return await repository.find_by_case(case_id, limit=limit, cursor=cursor)


async def add_case_tag(session: AsyncSession, case_id: uuid.UUID, tag: str) -> CaseTag:
    """Attach a tag, idempotently — re-adding an existing `(case_id, tag)`
    pair returns the existing row rather than raising, matching
    `case_tags`' unique-constraint semantics without a redundant duplicate
    error for a naturally idempotent action."""
    repository = CaseTagRepository(session)
    existing = await repository.find_one(case_id, tag)
    if existing is not None:
        return existing
    return await repository.add(CaseTag(case_id=case_id, tag=tag, created_at=datetime.now(UTC)))


async def remove_case_tag(session: AsyncSession, case_id: uuid.UUID, tag: str) -> bool:
    repository = CaseTagRepository(session)
    return await repository.delete_by_case_and_tag(case_id, tag)


async def list_case_tags(
    session: AsyncSession, case_id: uuid.UUID, *, limit: int = 200, cursor: uuid.UUID | None = None
) -> list[CaseTag]:
    repository = CaseTagRepository(session)
    return await repository.find_by_case(case_id, limit=limit, cursor=cursor)


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


async def _hydrate_attributed_iocs(
    session: AsyncSession, *, evidence_id: uuid.UUID
) -> list[dict[str, object]]:
    """Reduces this evidence's already-persisted, already-scored `IOC` rows
    to plain dicts (`{"evidence_id", "ioc_type", "composite_score"}`) for
    `CaseInvestigationState.extracted_indicators` — never re-extracts or
    re-scores an IOC (constitution §1.9); `IOC.composite_score` was already
    computed by `core.threat_intel`'s Threat Scoring Engine
    (`core/services/threat_intel_service.py`). Kept as plain dicts rather
    than a typed `core.threat_intel.models.ScoredIOC` per
    `core/agents/phishing_agent.py`'s docstring: `core/agents` has no import
    edge onto `core/threat_intel` (docs/dependency-rules.md rule 4)."""
    repository = IOCRepository(session)
    iocs = await repository.find_by_evidence(evidence_id)
    return [
        {
            "evidence_id": ioc.evidence_id,
            "ioc_type": ioc.ioc_type.value,
            "composite_score": ioc.composite_score,
        }
        for ioc in iocs
    ]


async def _run_specialist_agents(
    session: AsyncSession,
    *,
    case_id: uuid.UUID,
    evidence_items: list[NormalizedEvidence],
    evidence_id: uuid.UUID,
) -> CaseInvestigationState:
    """Rule 4d (module docstring): the one place `core/services` constructs
    a session-scoped `CaseMemory` and a fresh `AgentRegistry` before
    delegating to `core/graph`. Registers both concrete specialist agents
    built to date (`SocAnalystAgent`, `PhishingAgent`); which one(s) the
    Coordinator actually fans out to is decided by `required_capabilities`,
    computed per-artifact from its `EvidenceType` (`_required_capability_for`)
    — this is what lets a log upload and an email upload to the same Case
    each route to the correct specialist automatically."""
    case_memory = SQLiteCaseMemory(MemoryRepository(session))
    registry = AgentRegistry()
    registry.register(
        SocAnalystAgent(tool_registry=default_soc_analyst_tool_registry(), case_memory=case_memory)
    )
    registry.register(
        PhishingAgent(tool_registry=default_phishing_agent_tool_registry(), case_memory=case_memory)
    )
    engine = build_investigation_graph(agent_registry=registry)

    required_capability = _required_capability_for(evidence_items[0].evidence_type)
    attributed_iocs = await _hydrate_attributed_iocs(session, evidence_id=evidence_id)
    state = CaseInvestigationState(
        case_id=case_id,
        evidence=list(evidence_items),
        extracted_indicators=list(attributed_iocs),
        metadata={"required_capabilities": [required_capability]},
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
    event_publisher: CaseEventPublisher | None = None,
) -> CaseInvestigationResult:
    """The full blueprint §9 data-flow pipeline for one uploaded artifact:
    ingest -> extract IOCs -> generate Findings -> run SOC analysis,
    recording a `TimelineEvent` at each stage. Composes three already-
    complete, independently-tested pipelines plus this milestone's
    `SocAnalystAgent` run.

    A case moves from `OPEN` to `INVESTIGATING` automatically on its first
    evidence artifact (blueprint §8's lifecycle) — never on later uploads.
    """
    publisher = event_publisher or CaseEventPublisher()

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
        publisher.publish(
            CaseEvent(
                event_type=CaseEventType.EVIDENCE_ATTACHED,
                case_id=case_id,
                evidence_id=ingestion.evidence_id,
                detail=filename,
            )
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
            publisher.publish(
                CaseEvent(
                    event_type=CaseEventType.FINDING_ATTACHED,
                    case_id=case_id,
                    finding_id=finding_id,
                )
            )

        result_state = await _run_specialist_agents(
            session,
            case_id=case_id,
            evidence_items=[normalized],
            evidence_id=ingestion.evidence_id,
        )
        soc_risk_score, soc_risk_label = _extract_soc_risk(result_state)
        phishing_risk_score, phishing_risk_label = _extract_phishing_risk(result_state)
        for agent_name in (SocAnalystAgent.name, PhishingAgent.name):
            agent_output = result_state.agent_outputs.get(agent_name)
            if agent_output is not None:
                await _record_timeline(
                    session, case_id, TimelineEventType.AGENT_ANALYSIS, agent_output.thought
                )

        case = await get_case(session, case_id)
        if case is not None and case.status is CaseStatus.OPEN:
            await update_case_status(
                session, case_id, CaseStatus.INVESTIGATING, event_publisher=publisher
            )

        await recompute_case_risk_score(session, case_id)

        return CaseInvestigationResult(
            case_id=case_id,
            evidence_id=ingestion.evidence_id,
            ioc_count=extraction.ioc_count,
            created_finding_ids=generation.created_finding_ids,
            merged_finding_ids=generation.merged_finding_ids,
            soc_risk_score=soc_risk_score,
            soc_risk_label=soc_risk_label,
            phishing_risk_score=phishing_risk_score,
            phishing_risk_label=phishing_risk_label,
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


def _extract_phishing_risk(state: CaseInvestigationState) -> tuple[float | None, str | None]:
    """`PhishingAgent`'s counterpart to `_extract_soc_risk` — reads the
    highest risk score/label across this run's `PhishingVerdict` payload."""
    phishing_output = state.agent_outputs.get(PhishingAgent.name)
    if phishing_output is None:
        return None, None
    verdicts_payload = phishing_output.output.get("verdicts", [])
    if not verdicts_payload:
        return None, None
    top = max(verdicts_payload, key=lambda v: v["risk_score"])
    return top["risk_score"], top["risk_label"]
