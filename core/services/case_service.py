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
prompt-guard.md, docs/adr/0017-vulnerability-assessment-framework.md, and
docs/adr/0018-linux-security-threat-hunting-framework.md): this module *does*
import `core.agents.{registry, soc_analyst_agent, phishing_agent,
vulnerability_agent, threat_hunter_agent}` and
`core.memory.{case_memory,repository}` directly, to build a session-scoped
`SQLiteCaseMemory` and a *fresh* (never the process-wide cached)
`AgentRegistry` before delegating execution to
`core/graph/investigation_graph.py`. This is the one narrow reason: the
cached `default_agent_registry()` singleton would otherwise permanently bake
in whichever caller's `case_memory` (or lack of one) happened to register
`SocAnalystAgent`/`PhishingAgent`/`VulnerabilityAssessmentAgent`/
`ThreatHunterAgent` first. It also imports `core.parsers.models.{EvidenceType,
NormalizedEvidence, Severity}` directly for type reuse — the identical
sideways leaf-model precedent `core/db/models/case.py` (and `evidence.py`)
already established, not a new kind of exception. Reading
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
Calling `core.services.vulnerability_service.assess_vulnerabilities()`,
`core.services.linux_security_service.assess_linux_security()`,
`core.services.linux_advisor_service.assess_linux_command_input()`,
`core.services.web_security_service.assess_http_transaction()`, and
`core.services.owasp_security_service.assess_source_code()` is normal
sibling-service composition (the same reasoning already covers
`extract_threat_intelligence`/`generate_findings_for_case`); their already-
generated `VulnerabilityFinding`/`LinuxSecurityFinding`/`LinuxSecurityAdvice`/
`WebSecurityAdvice`/`SastAdvice` data is reduced to plain dicts before being
hydrated onto `CaseInvestigationState.vulnerability_records`/
`linux_security_records`/`linux_advisory_records`/`owasp_web_records`/
`owasp_security_records`, for the identical reason
`core/agents/vulnerability_agent.py`'s, `core/agents/threat_hunter_agent.py`'s,
`core/agents/linux_security_agent.py`'s, `core/agents/web_security_agent.py`'s,
and `core/agents/owasp_security_agent.py`'s docstrings document.
`assess_linux_command_input()`/`assess_http_transaction()`/
`assess_source_code()` are synchronous (no DB session parameter) —
ADR-0019's Linux Security Advisor Framework, ADR-0020's OWASP Web Security
Agent framework, and ADR-0021's OWASP Security Agent framework never
persist anything.

ADR-0022 (MITRE Mapping Agent) extends this module additively: importing
`core.agents.mitre_mapping_agent` directly is the same sibling-service/
agent-registration composition every prior specialist agent already
established, not a new exception. `_hydrate_mitre_mapping_records` reads
`json.loads(Finding.finding_data_json)` directly (never a typed
`core.findings.models.FindingRecord` import — this module has no import
edge onto `core/findings`; that edge belongs to `finding_service.py`
specifically, rule 4c) via `core.services.finding_service.
list_findings_for_case`, which is normal sibling-service composition, the
same reasoning that already covers `generate_findings_for_case`.
`MitreMappingAgent`'s tool registry needs `settings` (to load the vendored
MITRE dataset), so `_run_specialist_agents` and `build_investigation_graph`
both gained a `settings` parameter this session — additive, every other
caller of `build_investigation_graph` still works via its `Settings()`
default.

ADR-0023 (Incident Response Agent) extends this module additively:
importing `core.agents.incident_response_agent` directly is the same
sibling-service/agent-registration composition every prior specialist agent
already established. `_hydrate_incident_response_records` mirrors
`_hydrate_mitre_mapping_records` exactly (case-wide, `json.loads` on
`Finding.finding_data_json`, never a typed `core.findings` import).
`_persist_incident_response_plan` calls
`core.db.incident_response_plan_repository.IncidentResponsePlanRepository.
upsert_for_case` with the plan as a plain dict — this module still has no
import edge onto `core/incident_response` at all (that Pydantic model stays
imported only inside `core/db`, per that repository's own docstring), so no
new dependency-rules.md exception was needed for `case_service.py` itself;
the one new exception this ADR introduces (`docs/dependency-rules.md` rule
5b) is scoped to `core/tools/ir_tools.py`, not this module.

ADR-0024 (Report Generator Agent) extends this module additively: importing
`core.agents.report_generator_agent` directly is the same sibling-service/
agent-registration composition every prior specialist agent already
established. `_hydrate_incident_response_plan_record` reads this case's most
recently *persisted* `IncidentResponsePlanRow.plan_data_json` directly
(`json.loads`, never a typed `core.incident_response.models.
IncidentResponsePlan` import here — that import edge stays scoped to
`core/db`). `_persist_report` calls
`core.db.report_repository.ReportRepository.upsert_for_case` with the report
as a plain dict — this module still has no import edge onto
`core/reporting` at all (that Pydantic model stays imported only inside
`core/db`, per that repository's own docstring), so no new
dependency-rules.md exception was needed for `case_service.py` itself; the
one new exception this ADR introduces (`docs/dependency-rules.md` rule 5c)
is scoped to `core/tools/report_tools.py`, not this module.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession

from core.agents.incident_response_agent import (
    IncidentResponseAgent,
    default_incident_response_agent_tool_registry,
)
from core.agents.linux_security_agent import (
    LinuxSecurityAgent,
    default_linux_security_agent_tool_registry,
)
from core.agents.mitre_mapping_agent import (
    MitreMappingAgent,
    default_mitre_mapping_agent_tool_registry,
)
from core.agents.owasp_security_agent import (
    OwaspSecurityAgent,
    default_owasp_security_agent_tool_registry,
)
from core.agents.phishing_agent import PhishingAgent, default_phishing_agent_tool_registry
from core.agents.registry import AgentRegistry
from core.agents.report_generator_agent import (
    ReportGeneratorAgent,
    default_report_generator_agent_tool_registry,
)
from core.agents.soc_analyst_agent import SocAnalystAgent, default_soc_analyst_tool_registry
from core.agents.threat_hunter_agent import (
    ThreatHunterAgent,
    default_threat_hunter_agent_tool_registry,
)
from core.agents.vulnerability_agent import (
    VulnerabilityAssessmentAgent,
    default_vulnerability_agent_tool_registry,
)
from core.agents.web_security_agent import (
    WebSecurityAgent,
    default_web_security_agent_tool_registry,
)
from core.config import Settings
from core.db.case_note_repository import CaseNoteRepository
from core.db.case_repository import CaseRepository
from core.db.case_tag_repository import CaseTagRepository
from core.db.incident_response_plan_repository import IncidentResponsePlanRepository
from core.db.ioc_repository import IOCRepository
from core.db.models.case import Case, CasePriority, CaseStatus
from core.db.models.case_note import CaseNote
from core.db.models.case_tag import CaseTag
from core.db.models.timeline_event import TimelineEvent, TimelineEventType
from core.db.report_repository import ReportRepository
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
from core.services.finding_service import generate_findings_for_case, list_findings_for_case
from core.services.linux_advisor_service import assess_linux_command_input
from core.services.linux_security_service import assess_linux_security
from core.services.owasp_security_service import assess_source_code
from core.services.threat_intel_service import extract_threat_intelligence
from core.services.vulnerability_service import assess_vulnerabilities
from core.services.web_security_service import assess_http_transaction

_logger = get_logger(__name__)

#: `CaseStatus` values that map to a specific `CaseEventType` on transition;
#: every other target status publishes the generic `CASE_UPDATED` event.
_STATUS_TO_EVENT_TYPE: dict[CaseStatus, CaseEventType] = {
    CaseStatus.ESCALATED: CaseEventType.CASE_ESCALATED,
    CaseStatus.RESOLVED: CaseEventType.CASE_RESOLVED,
    CaseStatus.CLOSED: CaseEventType.CASE_CLOSED,
}

#: The capability names `SocAnalystAgent`/`PhishingAgent`/
#: `VulnerabilityAssessmentAgent`/`ThreatHunterAgent` declare — read from the
#: classes rather than re-declared as string literals here, so these can
#: never silently drift.
_SOC_ANALYST_CAPABILITY = SocAnalystAgent.capabilities[0].name
_PHISHING_CAPABILITY = PhishingAgent.capabilities[0].name
_VULNERABILITY_CAPABILITY = VulnerabilityAssessmentAgent.capabilities[0].name
_THREAT_HUNTING_CAPABILITY = ThreatHunterAgent.capabilities[0].name
_LINUX_ADVISORY_CAPABILITY = LinuxSecurityAgent.capabilities[0].name
_OWASP_WEB_SECURITY_CAPABILITY = WebSecurityAgent.capabilities[0].name
_OWASP_SOURCE_CODE_REVIEW_CAPABILITY = OwaspSecurityAgent.capabilities[0].name
_MITRE_MAPPING_CAPABILITY = MitreMappingAgent.capabilities[0].name
_INCIDENT_RESPONSE_CAPABILITY = IncidentResponseAgent.capabilities[0].name
_REPORT_GENERATION_CAPABILITY = ReportGeneratorAgent.capabilities[0].name

#: Which capabilities a newly-ingested artifact's `EvidenceType` requires —
#: the per-upload routing decision that lets the Coordinator fan out to the
#: right specialist(s) automatically (blueprint §7's Coordinator/Planning
#: Agent responsibility, closing M3's own demo criterion:
#: "upload mixed evidence to one Case and watch the Coordinator fan out to
#: both agents automatically"). A tuple, not a single string: `SSH_AUTH`/
#: `SYSLOG` now require *both* `_SOC_ANALYST_CAPABILITY` and
#: `_THREAT_HUNTING_CAPABILITY` (docs/adr/0018 point 6) — the Planning Agent
#: already fans out to every matched capability independently
#: (`core/agents/planning_agent.py`), so a single evidence type mapping to
#: more than one capability needed no framework change. Additive: any
#: `EvidenceType` not listed here falls back to `(_SOC_ANALYST_CAPABILITY,)`,
#: matching the pre-M2 behavior for every log-shaped format this framework
#: already parses.
_EVIDENCE_TYPE_CAPABILITIES: dict[EvidenceType, tuple[str, ...]] = {
    EvidenceType.EMAIL: (_PHISHING_CAPABILITY,),
    EvidenceType.NESSUS_XML: (_VULNERABILITY_CAPABILITY,),
    EvidenceType.NESSUS_CSV: (_VULNERABILITY_CAPABILITY,),
    EvidenceType.OPENVAS_XML: (_VULNERABILITY_CAPABILITY,),
    EvidenceType.OPENVAS_CSV: (_VULNERABILITY_CAPABILITY,),
    EvidenceType.SSH_AUTH: (_SOC_ANALYST_CAPABILITY, _THREAT_HUNTING_CAPABILITY),
    EvidenceType.SYSLOG: (_SOC_ANALYST_CAPABILITY, _THREAT_HUNTING_CAPABILITY),
    EvidenceType.LINUX_COMMAND_INPUT: (_LINUX_ADVISORY_CAPABILITY,),
    EvidenceType.HTTP_TRANSACTION: (_OWASP_WEB_SECURITY_CAPABILITY,),
    EvidenceType.SOURCE_CODE: (_OWASP_SOURCE_CODE_REVIEW_CAPABILITY,),
}

#: Evidence types `assess_vulnerabilities()` is actually run against —
#: running the vulnerability-extraction engine against a non-scan-report
#: artifact (a log, an email) would only ever produce candidates that fail
#: `VulnerabilityValidator`'s "has an identifying field" rule, wasted work
#: for a guaranteed-empty result (docs/adr/0017).
_VULNERABILITY_SCAN_EVIDENCE_TYPES: frozenset[EvidenceType] = frozenset(
    {
        EvidenceType.NESSUS_XML,
        EvidenceType.NESSUS_CSV,
        EvidenceType.OPENVAS_XML,
        EvidenceType.OPENVAS_CSV,
    }
)

#: Evidence types `assess_linux_security()` is actually run against —
#: deliberately **not** `EvidenceType.JSON`, even though a journald JSON
#: export is a plausible future Linux-security input: `JSON` evidence is
#: used generically elsewhere for arbitrary structured exports (e.g. EDR
#: alerts), so forcing Linux-security analysis onto every JSON upload would
#: be wrong (docs/adr/0018, mirroring ADR-0017 point 9's identical
#: scan-type gating reasoning).
_LINUX_SECURITY_EVIDENCE_TYPES: frozenset[EvidenceType] = frozenset(
    {EvidenceType.SSH_AUTH, EvidenceType.SYSLOG}
)

#: Evidence types `assess_linux_command_input()` is actually run against —
#: the Linux Security *Advisor* Framework (ADR-0019), deliberately distinct
#: from `_LINUX_SECURITY_EVIDENCE_TYPES` above (ADR-0018's *Threat Hunting*
#: Framework). Never overlapping: `LINUX_COMMAND_INPUT` is raw command/
#: permission text, not a log format.
_LINUX_ADVISOR_EVIDENCE_TYPES: frozenset[EvidenceType] = frozenset(
    {EvidenceType.LINUX_COMMAND_INPUT}
)

#: Evidence types `assess_http_transaction()` is actually run against — the
#: OWASP Web Security Agent framework (docs/adr/0020), never overlapping any
#: prior framework's evidence types: `HTTP_TRANSACTION` is raw HTTP
#: request/response transcript text, not a log format.
_WEB_SECURITY_EVIDENCE_TYPES: frozenset[EvidenceType] = frozenset({EvidenceType.HTTP_TRANSACTION})

#: Evidence types `assess_source_code()` is actually run against — the
#: OWASP Security Agent (AST SAST) framework (docs/adr/0021), never
#: overlapping any prior framework's evidence types: `SOURCE_CODE` is raw
#: source code text, not HTTP traffic or a log format.
_OWASP_SECURITY_EVIDENCE_TYPES: frozenset[EvidenceType] = frozenset({EvidenceType.SOURCE_CODE})


def _required_capabilities_for(evidence_type: EvidenceType) -> list[str]:
    """`_MITRE_MAPPING_CAPABILITY`/`_INCIDENT_RESPONSE_CAPABILITY` are both
    appended for every evidence type, regardless of what specialist(s) it
    also routes to (ADR-0022, ADR-0023): Finding generation (and therefore
    MITRE mapping, and now incident response synthesis) already runs
    unconditionally on every evidence upload
    (`generate_findings_for_case` in `investigate_new_evidence`), so both
    `MitreMappingAgent` and `IncidentResponseAgent` are cross-cutting rather
    than evidence-type-gated, exactly like blueprint §7 describes MITRE
    mapping ("used by SOC/Threat Hunting/Incident agents")."""
    capabilities = list(_EVIDENCE_TYPE_CAPABILITIES.get(evidence_type, (_SOC_ANALYST_CAPABILITY,)))
    capabilities.append(_MITRE_MAPPING_CAPABILITY)
    capabilities.append(_INCIDENT_RESPONSE_CAPABILITY)
    capabilities.append(_REPORT_GENERATION_CAPABILITY)
    return capabilities


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
    vulnerability_finding_count: int | None = None
    highest_vulnerability_score: float | None = None
    linux_security_finding_count: int | None = None
    highest_linux_security_risk_score: float | None = None
    linux_advisory_count: int | None = None
    highest_linux_advisory_risk_level: str | None = None
    owasp_web_finding_count: int | None = None
    highest_owasp_web_risk_level: str | None = None
    sast_finding_count: int | None = None
    highest_sast_risk_level: str | None = None
    mitre_technique_count: int | None = None
    mitre_distinct_group_count: int | None = None
    incident_response_recommendation_count: int | None = None
    incident_severity: str | None = None
    report_id: uuid.UUID | None = None
    report_type: str | None = None
    report_section_count: int | None = None
    report_confidence: float | None = None


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


async def _hydrate_mitre_mapping_records(
    session: AsyncSession, *, case_id: uuid.UUID, settings: Settings
) -> list[dict[str, object]]:
    """Reduces this case's already-persisted `Finding.mitre_mappings` (each
    `Finding.finding_data_json` is a serialized `core.findings.models.
    FindingRecord`, already produced by `generate_findings_for_case()`) to
    plain dicts for `CaseInvestigationState.mitre_mapping_records` — never
    re-maps a technique or recomputes a confidence (constitution §1.9).
    Reads `json.loads(row.finding_data_json)` directly rather than importing
    `core.findings.models.FindingRecord`: `core/services/case_service.py`
    has no documented import edge onto `core/findings` (rule 4c grants that
    edge to `finding_service.py` specifically), and the raw dict is all this
    function needs. Scoped to the whole case (every Finding, not just this
    upload's), matching blueprint §13's MITRE ATT&CK matrix heatmap, which
    is case-wide by definition."""
    rows = await list_findings_for_case(
        session, case_id, limit=settings.finding_max_candidates_per_case
    )
    records: list[dict[str, object]] = []
    for row in rows:
        try:
            data = json.loads(row.finding_data_json)
        except (TypeError, ValueError):
            _logger.warning(
                "mitre_mapping_hydration_skipped_malformed_finding", finding_id=str(row.id)
            )
            continue
        for mapping in data.get("mitre_mappings", []):
            if not isinstance(mapping, dict) or "technique_id" not in mapping:
                continue
            records.append(
                {
                    "finding_id": str(row.id),
                    "technique_id": mapping.get("technique_id"),
                    "tactic_ids": list(mapping.get("tactic_ids", ())),
                    "confidence": mapping.get("confidence", 0.0),
                    "mapping_source": mapping.get("mapping_source", ""),
                    "attack_spec_version": mapping.get("attack_spec_version", ""),
                    # Explainability requirement: "show exactly why each
                    # technique was selected" — the specific firing rule and
                    # its human-readable rationale, not just an ID/score.
                    "rule_id": mapping.get("rule_id", ""),
                    "rationale": mapping.get("rationale", ""),
                }
            )
    return records


async def _hydrate_incident_response_records(
    session: AsyncSession, *, case_id: uuid.UUID, settings: Settings
) -> list[dict[str, object]]:
    """Reduces this case's already-persisted `Finding` rows (title,
    severity, risk_score, confidence, and their own `mitre_mappings`) to
    plain dicts for `CaseInvestigationState.incident_response_finding_records`
    — never re-derives a severity/risk score/MITRE mapping (constitution
    §1.9). Mirrors `_hydrate_mitre_mapping_records` exactly: reads
    `json.loads(row.finding_data_json)` directly rather than importing
    `core.findings.models.FindingRecord` (this module has no import edge
    onto `core/findings`; that edge belongs to `finding_service.py`
    specifically, rule 4c). Scoped to the whole case, matching
    `_hydrate_mitre_mapping_records`'s identical case-wide scope
    (docs/adr/0023-incident-response-agent.md, Decision 1)."""
    rows = await list_findings_for_case(
        session, case_id, limit=settings.finding_max_candidates_per_case
    )
    records: list[dict[str, object]] = []
    for row in rows:
        try:
            data = json.loads(row.finding_data_json)
        except (TypeError, ValueError):
            _logger.warning(
                "incident_response_hydration_skipped_malformed_finding", finding_id=str(row.id)
            )
            continue
        mitre_mappings = [m for m in data.get("mitre_mappings", []) if isinstance(m, dict)]
        technique_ids = [m["technique_id"] for m in mitre_mappings if "technique_id" in m]
        tactic_ids = sorted(
            {tactic_id for m in mitre_mappings for tactic_id in m.get("tactic_ids", ())}
        )
        confidence = data.get("confidence")
        composite_confidence = (
            confidence.get("composite", 1.0) if isinstance(confidence, dict) else 1.0
        )
        explanation = data.get("explanation")
        evidence_summary = ""
        severity_rationale = ""
        if isinstance(explanation, dict):
            evidence_summary = str(explanation.get("evidence_summary", ""))
            severity_rationale = str(explanation.get("severity_rationale", ""))
        records.append(
            {
                "finding_id": str(row.id),
                "title": data.get("title", ""),
                "severity": data.get("severity", "info"),
                "risk_score": data.get("risk_score", 0.0),
                "confidence": composite_confidence,
                "mitre_technique_ids": technique_ids,
                "mitre_tactic_ids": tactic_ids,
                # Explainability requirement: real, evidence-specific text
                # (constitution §1.9's "no re-derivation" — this is read
                # straight through from `core.findings.models.
                # FindingExplanation`, never recomputed here).
                "evidence_summary": evidence_summary,
                "severity_rationale": severity_rationale,
            }
        )
    return records


async def _hydrate_incident_response_plan_record(
    session: AsyncSession, *, case_id: uuid.UUID
) -> dict[str, object] | None:
    """Reduces this case's most recently *persisted*
    `IncidentResponsePlanRow.plan_data_json` to a plain dict for
    `CaseInvestigationState.incident_response_plan_record` — never
    re-derives a severity/risk score/recommendation (constitution §1.9).
    Reads `json.loads(row.plan_data_json)` directly rather than importing
    `core.incident_response.models.IncidentResponsePlan` (this module has no
    import edge onto `core/incident_response`; that edge belongs to
    `core/db` specifically). Returns `None` if no plan has ever been
    persisted for this case yet — deliberately one run behind this run's own
    `IncidentResponseAgent` output (docs/adr/0024-report-generator-agent.md,
    Decision 2): this hydration happens *before* `engine.run(state)`, while
    this run's own plan is persisted only *after* the graph completes."""
    repository = IncidentResponsePlanRepository(session)
    row = await repository.find_by_case(case_id)
    if row is None:
        return None
    try:
        data = json.loads(row.plan_data_json)
    except (TypeError, ValueError):
        _logger.warning(
            "report_generation_hydration_skipped_malformed_incident_response_plan",
            case_id=str(case_id),
        )
        return None
    return data if isinstance(data, dict) else None


async def _run_specialist_agents(
    session: AsyncSession,
    *,
    case_id: uuid.UUID,
    evidence_items: list[NormalizedEvidence],
    evidence_id: uuid.UUID,
    settings: Settings,
    vulnerability_records: list[dict[str, object]] | None = None,
    linux_security_records: list[dict[str, object]] | None = None,
    linux_advisory_records: list[dict[str, object]] | None = None,
    owasp_web_records: list[dict[str, object]] | None = None,
    owasp_security_records: list[dict[str, object]] | None = None,
    mitre_mapping_records: list[dict[str, object]] | None = None,
    incident_response_finding_records: list[dict[str, object]] | None = None,
    incident_response_plan_record: dict[str, object] | None = None,
) -> CaseInvestigationState:
    """Rule 4d (module docstring): the one place `core/services` constructs
    a session-scoped `CaseMemory` and a fresh `AgentRegistry` before
    delegating to `core/graph`. Registers all ten concrete specialist
    agents built to date (`SocAnalystAgent`, `PhishingAgent`,
    `VulnerabilityAssessmentAgent`, `ThreatHunterAgent`,
    `LinuxSecurityAgent`, `WebSecurityAgent`, `OwaspSecurityAgent`,
    `MitreMappingAgent`, `IncidentResponseAgent`, `ReportGeneratorAgent`);
    which one(s) the
    Coordinator actually fans out to is decided by `required_capabilities`,
    computed per-artifact from its `EvidenceType`
    (`_required_capabilities_for`) — this is what lets a log upload, an
    email upload, a scan-report upload, and an SSH-auth/syslog upload to the
    same Case each route to the correct specialist(s) automatically. A
    single evidence type can now require more than one capability
    (`SSH_AUTH`/`SYSLOG` route to both `SocAnalystAgent` and
    `ThreatHunterAgent` — docs/adr/0018 point 6)."""
    case_memory = SQLiteCaseMemory(MemoryRepository(session))
    registry = AgentRegistry()
    registry.register(
        SocAnalystAgent(tool_registry=default_soc_analyst_tool_registry(), case_memory=case_memory)
    )
    registry.register(
        PhishingAgent(tool_registry=default_phishing_agent_tool_registry(), case_memory=case_memory)
    )
    registry.register(
        VulnerabilityAssessmentAgent(
            tool_registry=default_vulnerability_agent_tool_registry(), case_memory=case_memory
        )
    )
    registry.register(
        ThreatHunterAgent(
            tool_registry=default_threat_hunter_agent_tool_registry(), case_memory=case_memory
        )
    )
    registry.register(
        LinuxSecurityAgent(
            tool_registry=default_linux_security_agent_tool_registry(), case_memory=case_memory
        )
    )
    registry.register(
        WebSecurityAgent(
            tool_registry=default_web_security_agent_tool_registry(), case_memory=case_memory
        )
    )
    registry.register(
        OwaspSecurityAgent(
            tool_registry=default_owasp_security_agent_tool_registry(), case_memory=case_memory
        )
    )
    registry.register(
        MitreMappingAgent(
            tool_registry=default_mitre_mapping_agent_tool_registry(settings=settings)
        )
    )
    registry.register(
        IncidentResponseAgent(tool_registry=default_incident_response_agent_tool_registry())
    )
    registry.register(
        ReportGeneratorAgent(tool_registry=default_report_generator_agent_tool_registry())
    )
    engine = build_investigation_graph(agent_registry=registry, settings=settings)

    required_capabilities = _required_capabilities_for(evidence_items[0].evidence_type)
    attributed_iocs = await _hydrate_attributed_iocs(session, evidence_id=evidence_id)
    state = CaseInvestigationState(
        case_id=case_id,
        evidence=list(evidence_items),
        extracted_indicators=list(attributed_iocs),
        vulnerability_records=list(vulnerability_records or []),
        linux_security_records=list(linux_security_records or []),
        linux_advisory_records=list(linux_advisory_records or []),
        owasp_web_records=list(owasp_web_records or []),
        owasp_security_records=list(owasp_security_records or []),
        mitre_mapping_records=list(mitre_mapping_records or []),
        incident_response_finding_records=list(incident_response_finding_records or []),
        incident_response_plan_record=incident_response_plan_record,
        metadata={"required_capabilities": required_capabilities},
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
    ingest -> extract IOCs -> generate Findings -> (conditionally) assess
    vulnerabilities -> (conditionally) assess Linux security -> run
    specialist agents, recording a `TimelineEvent` at each stage. Composes
    several already-complete, independently-tested pipelines plus this
    milestone's specialist-agent run.

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

        vulnerability_records: list[dict[str, object]] = []
        if normalized.evidence_type in _VULNERABILITY_SCAN_EVIDENCE_TYPES:
            assessment = await assess_vulnerabilities(
                session, case_id=case_id, evidence=normalized, settings=settings
            )
            vulnerability_records = [
                {
                    "cve_id": finding.cve_id,
                    "plugin_id": finding.plugin_id,
                    "title": finding.title,
                    "severity": finding.severity.value,
                    "priority": finding.priority.value,
                    "composite_score": finding.composite_score,
                    "affected_asset_ids": list(finding.affected_asset_ids),
                }
                for finding in assessment.normalized_vulnerability_intel.findings
            ]
            await _record_timeline(
                session,
                case_id,
                TimelineEventType.VULNERABILITY_ASSESSED,
                f"{assessment.vulnerability_count} vulnerability record(s), "
                f"{assessment.finding_count} finding(s) assessed from '{filename}'.",
            )

        linux_security_records: list[dict[str, object]] = []
        if normalized.evidence_type in _LINUX_SECURITY_EVIDENCE_TYPES:
            linux_assessment = await assess_linux_security(
                session, case_id=case_id, evidence=normalized, settings=settings
            )
            linux_security_records = [
                {
                    "category": finding.category.value,
                    "subject": finding.subject,
                    "subject_type": finding.subject_type,
                    "title": finding.title,
                    "severity": finding.severity.value,
                    "composite_score": finding.composite_score,
                    "occurrence_count": finding.occurrence_count,
                }
                for finding in linux_assessment.normalized_linux_security_intel.findings
            ]
            await _record_timeline(
                session,
                case_id,
                TimelineEventType.LINUX_SECURITY_FINDING_DETECTED,
                f"{linux_assessment.candidate_count} Linux security candidate(s), "
                f"{linux_assessment.finding_count} finding(s) detected from '{filename}'.",
            )

        linux_advisory_records: list[dict[str, object]] = []
        if normalized.evidence_type in _LINUX_ADVISOR_EVIDENCE_TYPES:
            advisory_assessment = assess_linux_command_input(
                case_id=case_id, evidence=normalized, settings=settings
            )
            advice = advisory_assessment.advice
            for command_risk in advice.analyzed_commands:
                linux_advisory_records.append(
                    {
                        "kind": "command",
                        "command_name": command_risk.command.command_name,
                        "raw_text": command_risk.command.raw_text,
                        "severity": command_risk.severity.value,
                        "confidence": command_risk.confidence,
                        "explanation": command_risk.explanation,
                        "matched_rule_count": len(command_risk.matched_rule_ids),
                    }
                )
            for permission_risk in advice.permission_analyses:
                linux_advisory_records.append(
                    {
                        "kind": "permission",
                        "filename": permission_risk.permission.filename,
                        "raw_text": permission_risk.permission.raw_text,
                        "severity": permission_risk.severity.value,
                        "confidence": permission_risk.confidence,
                        "explanation": permission_risk.explanation,
                        "matched_rule_count": len(permission_risk.matched_rule_ids),
                    }
                )
            for recommendation in advice.hardening_recommendations:
                linux_advisory_records.append(
                    {
                        "kind": "hardening",
                        "category": recommendation.category.value,
                        "recommendation": recommendation.recommendation,
                        "is_baseline": recommendation.is_baseline,
                    }
                )
            linux_advisory_records.append(
                {
                    "kind": "summary",
                    "overall_risk_level": advice.overall_risk_level.value,
                    "overall_confidence": advice.overall_confidence,
                    "overall_explanation": advice.overall_explanation,
                    "skipped_line_count": advice.skipped_line_count,
                }
            )
            await _record_timeline(
                session,
                case_id,
                TimelineEventType.LINUX_ADVISORY_ASSESSED,
                f"{len(advice.analyzed_commands)} command(s), "
                f"{len(advice.permission_analyses)} permission entr(ies) advised on from "
                f"'{filename}'; overall risk '{advice.overall_risk_level.value}'.",
            )

        owasp_web_records: list[dict[str, object]] = []
        if normalized.evidence_type in _WEB_SECURITY_EVIDENCE_TYPES:
            web_security_assessment = assess_http_transaction(
                case_id=case_id, evidence=normalized, settings=settings
            )
            web_advice = web_security_assessment.advice
            for owasp_finding in web_advice.owasp_findings:
                owasp_web_records.append(
                    {
                        "kind": "finding",
                        "category": owasp_finding.category.value,
                        "severity": owasp_finding.severity.value,
                        "confidence": owasp_finding.confidence,
                        "evidence_reference": owasp_finding.evidence_reference,
                        "explanation": owasp_finding.explanation,
                        "recommended_remediation": owasp_finding.recommended_remediation,
                        "source": owasp_finding.source,
                    }
                )
            owasp_web_records.append(
                {
                    "kind": "summary",
                    "overall_risk_level": web_advice.overall_risk_level.value,
                    "overall_confidence": web_advice.overall_confidence,
                    "overall_explanation": web_advice.overall_explanation,
                    "skipped_line_count": web_advice.skipped_line_count,
                }
            )
            await _record_timeline(
                session,
                case_id,
                TimelineEventType.OWASP_WEB_ASSESSED,
                f"{len(web_advice.owasp_findings)} OWASP-mapped finding(s) assessed from "
                f"'{filename}'; overall risk '{web_advice.overall_risk_level.value}'.",
            )

        owasp_security_records: list[dict[str, object]] = []
        if normalized.evidence_type in _OWASP_SECURITY_EVIDENCE_TYPES:
            sast_assessment = assess_source_code(
                case_id=case_id, evidence=normalized, settings=settings
            )
            sast_advice = sast_assessment.advice
            for sast_finding in sast_advice.sast_findings:
                owasp_security_records.append(
                    {
                        "kind": "finding",
                        "category": sast_finding.category.value,
                        "owasp_category": sast_finding.owasp_category.value,
                        "cwe_id": sast_finding.cwe_id,
                        "severity": sast_finding.severity.value,
                        "confidence": sast_finding.confidence,
                        "evidence_reference": sast_finding.evidence_reference,
                        "explanation": sast_finding.explanation,
                        "recommended_remediation": sast_finding.recommended_remediation,
                        "source": sast_finding.source,
                    }
                )
            owasp_security_records.append(
                {
                    "kind": "summary",
                    "language": sast_advice.language.value,
                    "overall_risk_level": sast_advice.overall_risk_level.value,
                    "overall_confidence": sast_advice.overall_confidence,
                    "overall_explanation": sast_advice.overall_explanation,
                    "parse_degraded": sast_advice.parse_degraded,
                }
            )
            await _record_timeline(
                session,
                case_id,
                TimelineEventType.SAST_ASSESSED,
                f"{len(sast_advice.sast_findings)} SAST finding(s) assessed from "
                f"'{filename}' ({sast_advice.language.value}); overall risk "
                f"'{sast_advice.overall_risk_level.value}'.",
            )

        mitre_mapping_records = await _hydrate_mitre_mapping_records(
            session, case_id=case_id, settings=settings
        )
        incident_response_finding_records = await _hydrate_incident_response_records(
            session, case_id=case_id, settings=settings
        )
        incident_response_plan_record = await _hydrate_incident_response_plan_record(
            session, case_id=case_id
        )

        result_state = await _run_specialist_agents(
            session,
            case_id=case_id,
            evidence_items=[normalized],
            evidence_id=ingestion.evidence_id,
            settings=settings,
            vulnerability_records=vulnerability_records,
            linux_security_records=linux_security_records,
            linux_advisory_records=linux_advisory_records,
            owasp_web_records=owasp_web_records,
            owasp_security_records=owasp_security_records,
            mitre_mapping_records=mitre_mapping_records,
            incident_response_finding_records=incident_response_finding_records,
            incident_response_plan_record=incident_response_plan_record,
        )
        soc_risk_score, soc_risk_label = _extract_soc_risk(result_state)
        phishing_risk_score, phishing_risk_label = _extract_phishing_risk(result_state)
        vulnerability_finding_count_from_agent, highest_vulnerability_score = (
            _extract_vulnerability_assessment(result_state)
        )
        linux_security_finding_count, highest_linux_security_risk_score = _extract_threat_hunting(
            result_state
        )
        linux_advisory_count, highest_linux_advisory_risk_level = _extract_linux_advisory(
            result_state
        )
        owasp_web_finding_count, highest_owasp_web_risk_level = _extract_web_security(result_state)
        sast_finding_count, highest_sast_risk_level = _extract_owasp_security(result_state)
        mitre_technique_count, mitre_distinct_group_count = _extract_mitre_mapping(result_state)
        for agent_name in (
            SocAnalystAgent.name,
            PhishingAgent.name,
            VulnerabilityAssessmentAgent.name,
            ThreatHunterAgent.name,
            LinuxSecurityAgent.name,
            WebSecurityAgent.name,
            OwaspSecurityAgent.name,
            MitreMappingAgent.name,
            IncidentResponseAgent.name,
            ReportGeneratorAgent.name,
        ):
            agent_output = result_state.agent_outputs.get(agent_name)
            if agent_output is not None:
                await _record_timeline(
                    session, case_id, TimelineEventType.AGENT_ANALYSIS, agent_output.thought
                )

        (
            incident_response_recommendation_count,
            incident_severity,
        ) = await _persist_incident_response_plan(session, case_id=case_id, state=result_state)
        (
            report_id,
            report_type,
            report_section_count,
            report_confidence,
        ) = await _persist_report(session, case_id=case_id, state=result_state)

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
            vulnerability_finding_count=vulnerability_finding_count_from_agent,
            highest_vulnerability_score=highest_vulnerability_score,
            linux_security_finding_count=linux_security_finding_count,
            highest_linux_security_risk_score=highest_linux_security_risk_score,
            linux_advisory_count=linux_advisory_count,
            highest_linux_advisory_risk_level=highest_linux_advisory_risk_level,
            owasp_web_finding_count=owasp_web_finding_count,
            highest_owasp_web_risk_level=highest_owasp_web_risk_level,
            sast_finding_count=sast_finding_count,
            highest_sast_risk_level=highest_sast_risk_level,
            mitre_technique_count=mitre_technique_count,
            mitre_distinct_group_count=mitre_distinct_group_count,
            incident_response_recommendation_count=incident_response_recommendation_count,
            incident_severity=incident_severity,
            report_id=report_id,
            report_type=report_type,
            report_section_count=report_section_count,
            report_confidence=report_confidence,
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


def _extract_vulnerability_assessment(
    state: CaseInvestigationState,
) -> tuple[int | None, float | None]:
    """`VulnerabilityAssessmentAgent`'s counterpart to `_extract_soc_risk` —
    reads the finding count and highest composite score out of this run's
    `VulnerabilityAssessment` payload."""
    vulnerability_output = state.agent_outputs.get(VulnerabilityAssessmentAgent.name)
    if vulnerability_output is None:
        return None, None
    assessment = vulnerability_output.output.get("assessment")
    if not assessment:
        return None, None
    return assessment["finding_count"], assessment["highest_composite_score"]


def _extract_threat_hunting(
    state: CaseInvestigationState,
) -> tuple[int | None, float | None]:
    """`ThreatHunterAgent`'s counterpart to `_extract_vulnerability_assessment`
    — reads the finding count and highest composite score out of this run's
    `ThreatHuntingReport` payload."""
    threat_hunting_output = state.agent_outputs.get(ThreatHunterAgent.name)
    if threat_hunting_output is None:
        return None, None
    report = threat_hunting_output.output.get("report")
    if not report:
        return None, None
    return report["finding_count"], report["highest_composite_score"]


def _extract_linux_advisory(state: CaseInvestigationState) -> tuple[int | None, str | None]:
    """`LinuxSecurityAgent`'s counterpart to `_extract_threat_hunting` —
    reads the total flagged-finding count and overall risk level out of
    this run's `LinuxSecurityAdvice` payload."""
    linux_advisory_output = state.agent_outputs.get(LinuxSecurityAgent.name)
    if linux_advisory_output is None:
        return None, None
    advice = linux_advisory_output.output.get("advice")
    if not advice:
        return None, None
    count = advice["flagged_command_count"] + advice["flagged_permission_count"]
    return count, advice["overall_risk_level"]


def _extract_web_security(state: CaseInvestigationState) -> tuple[int | None, str | None]:
    """`WebSecurityAgent`'s counterpart to `_extract_linux_advisory` — reads
    the total OWASP-mapped finding count and overall risk level out of this
    run's `WebSecurityAdvice` payload."""
    web_security_output = state.agent_outputs.get(WebSecurityAgent.name)
    if web_security_output is None:
        return None, None
    advice = web_security_output.output.get("advice")
    if not advice:
        return None, None
    return advice["finding_count"], advice["overall_risk_level"]


def _extract_owasp_security(state: CaseInvestigationState) -> tuple[int | None, str | None]:
    """`OwaspSecurityAgent`'s counterpart to `_extract_web_security` — reads
    the total SAST finding count and overall risk level out of this run's
    `SastAdvice` payload."""
    owasp_security_output = state.agent_outputs.get(OwaspSecurityAgent.name)
    if owasp_security_output is None:
        return None, None
    advice = owasp_security_output.output.get("advice")
    if not advice:
        return None, None
    return advice["finding_count"], advice["overall_risk_level"]


def _extract_mitre_mapping(state: CaseInvestigationState) -> tuple[int | None, int | None]:
    """`MitreMappingAgent`'s counterpart to `_extract_owasp_security` — reads
    the resolved technique count and distinct threat-group count out of this
    run's `MitreCaseMappingSummary` payload. Returns `(None, None)` for the
    documented "unmapped" degraded outcome (no summary was produced), never
    `(0, 0)` — the two are not the same thing (constitution §7's
    "insufficient evidence" vs. "no threats found" distinction)."""
    mitre_output = state.agent_outputs.get(MitreMappingAgent.name)
    if mitre_output is None:
        return None, None
    summary = mitre_output.output.get("summary")
    if not summary:
        return None, None
    return summary["technique_count"], summary["distinct_group_count"]


async def _persist_incident_response_plan(
    session: AsyncSession, *, case_id: uuid.UUID, state: CaseInvestigationState
) -> tuple[int | None, str | None]:
    """Persists this run's `IncidentResponsePlan` (if `IncidentResponseAgent`
    produced one) via `IncidentResponsePlanRepository.upsert_for_case` —
    passing the plan through as the plain dict `AgentExecutionResult.output`
    already carries, never importing `core.incident_response.models.
    IncidentResponsePlan` here (see `IncidentResponsePlanRepository`'s
    docstring for why that stays a `core/db`-only import). Returns
    `(None, None)` for the documented "no findings yet" DEGRADED outcome (no
    plan to persist) — never persists a placeholder, mirroring
    `_extract_mitre_mapping`'s identical "insufficient evidence" distinction."""
    output = state.agent_outputs.get(IncidentResponseAgent.name)
    if output is None:
        return None, None
    plan_data = output.output.get("plan")
    if not plan_data:
        return None, None

    repository = IncidentResponsePlanRepository(session)
    await repository.upsert_for_case(case_id, plan_data)

    recommendation_count = len(plan_data.get("recommendations", []))
    incident_severity = plan_data.get("incident_severity")
    await _record_timeline(
        session,
        case_id,
        TimelineEventType.INCIDENT_RESPONSE_PLAN_GENERATED,
        f"{recommendation_count} response recommendation(s) generated; "
        f"incident severity '{incident_severity}'.",
    )
    return recommendation_count, incident_severity


async def _persist_report(
    session: AsyncSession, *, case_id: uuid.UUID, state: CaseInvestigationState
) -> tuple[uuid.UUID | None, str | None, int | None, float | None]:
    """Persists this run's `GeneratedReport` (if `ReportGeneratorAgent`
    produced one) via `ReportRepository.upsert_for_case` — passing the
    report through as the plain dict `AgentExecutionResult.output` already
    carries, never importing `core.reporting.models.GeneratedReport` here
    (see `ReportRepository`'s docstring for why that stays a `core/db`-only
    import). Returns `(None, None, None, None)` for the documented
    "insufficient evidence" DEGRADED-with-no-report outcome — never persists
    a placeholder, mirroring `_persist_incident_response_plan`'s identical
    "insufficient evidence" distinction."""
    output = state.agent_outputs.get(ReportGeneratorAgent.name)
    if output is None:
        return None, None, None, None
    report_data = output.output.get("report")
    if not report_data:
        return None, None, None, None

    repository = ReportRepository(session)
    row = await repository.upsert_for_case(case_id, report_data)

    section_count = len(report_data.get("sections", []))
    report_type = report_data.get("report_type")
    confidence = report_data.get("confidence")
    await _record_timeline(
        session,
        case_id,
        TimelineEventType.REPORT_GENERATED,
        f"'{report_type}' report generated with {section_count} section(s).",
    )
    return row.id, report_type, section_count, confidence
