"""`IncidentInputFinding` — the one normalized shape every upstream subsystem's
already-computed signal is reduced to before `response_plan_engine.py` ever
sees it (constitution §1.9: this package only synthesizes a response from
values other subsystems already computed; it never re-derives a severity,
a risk score, or a MITRE mapping itself).

`core/agents/incident_response_agent.py` is the one place these get built —
from the case's persisted `Finding` rows (SOC Analyst / Threat Hunting /
Phishing-derived, case-wide) and from the current upload's already-hydrated
`vulnerability_records`/`linux_security_records`/`linux_advisory_records`/
`owasp_web_records`/`owasp_security_records`/`mitre_mapping_records` fields
on `CaseInvestigationState` (docs/adr/0023-incident-response-agent.md,
Decision 1). Kept in its own module (not `models.py`) because it is an
*engine input contract*, distinct from the task-named output models
`models.py` defines.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from core.incident_response.models import IncidentSeverity


class IncidentInputFinding(BaseModel):
    """One already-assessed signal from any upstream subsystem, normalized
    to a common shape this package's rule engine can match against."""

    model_config = ConfigDict(frozen=True)

    finding_id: str = ""
    source: str = ""
    title: str = ""
    severity: IncidentSeverity = IncidentSeverity.INFO
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    mitre_technique_ids: tuple[str, ...] = ()
    mitre_tactic_ids: tuple[str, ...] = ()
    #: A lowercased keyword bag pulled from title/description/category —
    #: used only as the documented fallback when no MITRE tactic is present
    #: (`playbook_rules.py`), never the primary signal.
    keywords: tuple[str, ...] = ()
    target: str = ""
