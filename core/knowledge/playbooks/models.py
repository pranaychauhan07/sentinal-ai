"""Typed contracts for `data/knowledge/security_best_practices.yaml` and
`data/knowledge/incident_response_guidance.yaml` — together, the
`SECURITY_PLAYBOOK` knowledge source (ADR-0027): general hardening/best-
practice guidance and NIST SP 800-61 incident-response-lifecycle guidance.
Both are read-only reference content, distinct from
`core/incident_response`'s deterministic, case-specific response-plan
engine.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class BestPracticeEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    title: str
    category: str
    guidance: str


class IncidentResponsePhaseGuidance(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    phase: str
    guidance: str
