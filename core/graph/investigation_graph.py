"""The Case Investigation Graph — blueprint §6's `investigation_graph.py`.

Wires the Coordinator (which internally delegates to the Planning Agent by
direct call, not a graph edge — see `core/agents/coordinator.py`'s docstring
for why) plus eight concrete specialist agents (Milestone M1/M2/M4 plus
`docs/adr/0020`/`docs/adr/0021`/`docs/adr/0022` — M4 is fully closed, M2 is
now fully closed too): `SocAnalystAgent` (`log_analysis`), `PhishingAgent`
(`email_triage`), `VulnerabilityAssessmentAgent`
(`vulnerability_assessment`), `ThreatHunterAgent`
(`cross_log_threat_hunting`,
docs/adr/0018-linux-security-threat-hunting-framework.md),
`LinuxSecurityAgent` (`linux_security_advisory`,
docs/adr/0019-linux-security-advisor-agent.md), `WebSecurityAgent`
(`owasp_web_security_assessment`,
docs/adr/0020-owasp-web-security-agent.md), `OwaspSecurityAgent`
(`owasp_source_code_review`,
docs/adr/0021-owasp-security-agent-ast-sast.md), and `MitreMappingAgent`
(`mitre_technique_mapping`, docs/adr/0022-mitre-mapping-agent.md). The
Planning Agent's capability-matching decides which of them a given case's
declared `required_capabilities` route to; the conditional edge out of the
Coordinator resolves to whichever specialist(s) that plan names, or `END` if
none. A single evidence type (`SYSLOG`) can require both `log_analysis` and
`cross_log_threat_hunting` in the same run, and — unlike every other
specialist here — `mitre_technique_mapping` is appended to *every* evidence
type's required capabilities by `core/services/case_service.py`
(`_required_capabilities_for`), since MITRE mapping is cross-cutting, not
evidence-type-specific (ADR-0022) — the Planning Agent already fans out to
every matched capability independently, so none of this needed a framework
change (ADR-0018 point 6).

Adding another specialist agent later means exactly the same three steps
these eight followed: implement it (`core/agents/`), register it in the
`AgentRegistry` passed to `build_investigation_graph`, and add two lines
here — `engine.add_agent_node(name)` and `engine.add_edge(name, END)`.
`WorkflowEngine` and `router.py` need zero changes for that to work, which is
the property this milestone's brief asked for: "the framework should support
future expansion without modification."
"""

from __future__ import annotations

from langgraph.graph import END

from core.agents.coordinator import CoordinatorAgent
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
from core.agents.planning_agent import PlanningAgent
from core.agents.registry import AgentRegistry, default_agent_registry
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
from core.graph.events import EventBus
from core.graph.failure_recovery import FailureRecoveryPolicy
from core.graph.retry import RetryPolicy
from core.graph.routing import route_from_coordinator
from core.graph.state import CaseInvestigationState
from core.graph.workflow_engine import WorkflowEngine
from core.memory.interfaces import CaseMemory


def _ensure_framework_agents_registered(registry: AgentRegistry) -> None:
    if not registry.has(PlanningAgent.name):
        registry.register(PlanningAgent(agent_registry=registry))
    if not registry.has(CoordinatorAgent.name):
        planner = registry.get(PlanningAgent.name)
        if not isinstance(planner, PlanningAgent):
            raise TypeError(
                f"Registry entry '{PlanningAgent.name}' is not a PlanningAgent instance."
            )
        registry.register(CoordinatorAgent(planning_agent=planner))


def _ensure_soc_analyst_registered(
    registry: AgentRegistry, *, case_memory: CaseMemory | None
) -> None:
    """Auto-registers `SocAnalystAgent` with `case_memory=None` — the
    correct, documented default for any caller not supplying a session-
    scoped memory (constitution: "every agent must work correctly with
    case_memory=None"). A caller wanting real memory (`core/services/
    case_service.py`, docs/adr/0014 rule 4d) pre-registers its own instance
    into a *fresh* `AgentRegistry` before calling `build_investigation_graph`
    — this idempotency check then leaves that instance untouched. Never
    called against the process-wide cached `default_agent_registry()` with a
    real `case_memory`: doing so would permanently bake in whichever caller
    happened to run first (see docs/adr/0014 for why this function takes
    `case_memory` as an explicit parameter instead of constructing one
    itself)."""
    if registry.has(SocAnalystAgent.name):
        return
    registry.register(
        SocAnalystAgent(tool_registry=default_soc_analyst_tool_registry(), case_memory=case_memory)
    )


def _ensure_phishing_agent_registered(
    registry: AgentRegistry, *, case_memory: CaseMemory | None
) -> None:
    """Mirrors `_ensure_soc_analyst_registered`'s idempotency/`case_memory`
    contract exactly — same reasoning, same caveat about never calling this
    against the process-wide cached `default_agent_registry()` with a real
    `case_memory`."""
    if registry.has(PhishingAgent.name):
        return
    registry.register(
        PhishingAgent(tool_registry=default_phishing_agent_tool_registry(), case_memory=case_memory)
    )


def _ensure_vulnerability_agent_registered(
    registry: AgentRegistry, *, case_memory: CaseMemory | None
) -> None:
    """Mirrors `_ensure_soc_analyst_registered`'s idempotency/`case_memory`
    contract exactly — same reasoning, same caveat about never calling this
    against the process-wide cached `default_agent_registry()` with a real
    `case_memory`."""
    if registry.has(VulnerabilityAssessmentAgent.name):
        return
    registry.register(
        VulnerabilityAssessmentAgent(
            tool_registry=default_vulnerability_agent_tool_registry(), case_memory=case_memory
        )
    )


def _ensure_threat_hunter_agent_registered(
    registry: AgentRegistry, *, case_memory: CaseMemory | None
) -> None:
    """Mirrors `_ensure_soc_analyst_registered`'s idempotency/`case_memory`
    contract exactly — same reasoning, same caveat about never calling this
    against the process-wide cached `default_agent_registry()` with a real
    `case_memory`."""
    if registry.has(ThreatHunterAgent.name):
        return
    registry.register(
        ThreatHunterAgent(
            tool_registry=default_threat_hunter_agent_tool_registry(), case_memory=case_memory
        )
    )


def _ensure_linux_security_agent_registered(
    registry: AgentRegistry, *, case_memory: CaseMemory | None
) -> None:
    """Mirrors `_ensure_soc_analyst_registered`'s idempotency/`case_memory`
    contract exactly — same reasoning, same caveat about never calling this
    against the process-wide cached `default_agent_registry()` with a real
    `case_memory`."""
    if registry.has(LinuxSecurityAgent.name):
        return
    registry.register(
        LinuxSecurityAgent(
            tool_registry=default_linux_security_agent_tool_registry(), case_memory=case_memory
        )
    )


def _ensure_web_security_agent_registered(
    registry: AgentRegistry, *, case_memory: CaseMemory | None
) -> None:
    """Mirrors `_ensure_soc_analyst_registered`'s idempotency/`case_memory`
    contract exactly — same reasoning, same caveat about never calling this
    against the process-wide cached `default_agent_registry()` with a real
    `case_memory`."""
    if registry.has(WebSecurityAgent.name):
        return
    registry.register(
        WebSecurityAgent(
            tool_registry=default_web_security_agent_tool_registry(), case_memory=case_memory
        )
    )


def _ensure_owasp_security_agent_registered(
    registry: AgentRegistry, *, case_memory: CaseMemory | None
) -> None:
    """Mirrors `_ensure_soc_analyst_registered`'s idempotency/`case_memory`
    contract exactly — same reasoning, same caveat about never calling this
    against the process-wide cached `default_agent_registry()` with a real
    `case_memory`."""
    if registry.has(OwaspSecurityAgent.name):
        return
    registry.register(
        OwaspSecurityAgent(
            tool_registry=default_owasp_security_agent_tool_registry(), case_memory=case_memory
        )
    )


def _ensure_mitre_mapping_agent_registered(registry: AgentRegistry, *, settings: Settings) -> None:
    """Mirrors `_ensure_soc_analyst_registered`'s idempotency contract, but
    takes `settings` instead of `case_memory` — `MitreMappingAgent` has no
    memory dependency; its tool needs a loaded `MitreLookup`, built from
    `settings` (docs/dependency-rules.md rule 4c: `core/agents` may import
    `core/knowledge` directly for MITRE mapping)."""
    if registry.has(MitreMappingAgent.name):
        return
    registry.register(
        MitreMappingAgent(
            tool_registry=default_mitre_mapping_agent_tool_registry(settings=settings)
        )
    )


def build_investigation_graph(
    *,
    agent_registry: AgentRegistry | None = None,
    case_memory: CaseMemory | None = None,
    event_bus: EventBus | None = None,
    retry_policy: RetryPolicy | None = None,
    recovery_policy: FailureRecoveryPolicy | None = None,
    settings: Settings | None = None,
) -> WorkflowEngine:
    """Construct the Case Investigation workflow, deliberately left
    uncompiled: `WorkflowEngine.compile`/`run` resolve node/router wiring
    lazily, so a caller (a test, or a future milestone) may still call
    `engine.add_agent_node(...)` for additional specialist agents *after*
    this returns, before running it. Returns the `WorkflowEngine` rather
    than a compiled graph directly so callers/tests can inspect
    `node_names` before running it.

    `case_memory` is only consulted when `SocAnalystAgent` isn't already
    registered on `agent_registry` (see `_ensure_soc_analyst_registered`) —
    ignored if a caller pre-registered their own instance. `settings`
    defaults to `Settings()` when omitted (every field has a default) and is
    consulted the same way for `MitreMappingAgent` (see
    `_ensure_mitre_mapping_agent_registered`)."""
    registry = agent_registry or default_agent_registry()
    resolved_settings = settings or Settings()
    _ensure_framework_agents_registered(registry)
    _ensure_soc_analyst_registered(registry, case_memory=case_memory)
    _ensure_phishing_agent_registered(registry, case_memory=case_memory)
    _ensure_vulnerability_agent_registered(registry, case_memory=case_memory)
    _ensure_threat_hunter_agent_registered(registry, case_memory=case_memory)
    _ensure_linux_security_agent_registered(registry, case_memory=case_memory)
    _ensure_web_security_agent_registered(registry, case_memory=case_memory)
    _ensure_owasp_security_agent_registered(registry, case_memory=case_memory)
    _ensure_mitre_mapping_agent_registered(registry, settings=resolved_settings)

    engine = WorkflowEngine(
        agent_registry=registry,
        event_bus=event_bus,
        retry_policy=retry_policy,
        recovery_policy=recovery_policy,
    )
    engine.add_agent_node(CoordinatorAgent.name)
    engine.set_entry(CoordinatorAgent.name)
    engine.add_conditional_edges(CoordinatorAgent.name, route_from_coordinator)
    engine.add_agent_node(SocAnalystAgent.name)
    engine.add_edge(SocAnalystAgent.name, END)
    engine.add_agent_node(PhishingAgent.name)
    engine.add_edge(PhishingAgent.name, END)
    engine.add_agent_node(VulnerabilityAssessmentAgent.name)
    engine.add_edge(VulnerabilityAssessmentAgent.name, END)
    engine.add_agent_node(ThreatHunterAgent.name)
    engine.add_edge(ThreatHunterAgent.name, END)
    engine.add_agent_node(LinuxSecurityAgent.name)
    engine.add_edge(LinuxSecurityAgent.name, END)
    engine.add_agent_node(WebSecurityAgent.name)
    engine.add_edge(WebSecurityAgent.name, END)
    engine.add_agent_node(OwaspSecurityAgent.name)
    engine.add_edge(OwaspSecurityAgent.name, END)
    engine.add_agent_node(MitreMappingAgent.name)
    engine.add_edge(MitreMappingAgent.name, END)
    return engine


def run_investigation(
    state: CaseInvestigationState, *, engine: WorkflowEngine | None = None
) -> CaseInvestigationState:
    """Convenience entry point: build (or reuse) the graph and run one case
    through it. `core/services/case_service.py` (Milestone M1+) will be the
    real caller of this once a case service exists."""
    return (engine or build_investigation_graph()).run(state)
