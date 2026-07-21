"""``IncidentResponsePlanGenerationTool`` — blueprint's exact named
`ir_tools.py`: the Incident Response Agent's deterministic response-plan
generation tool.

Unlike `owasp_tools.py`/`web_security_tools.py` (thin aggregators of an
already-computed value, deliberately dict-shaped, no cross-leaf import),
this tool's `run()` is a thin wrapper around
`core.incident_response.response_plan_engine.ResponsePlanEngine` — the
actual severity classification / rule matching / prioritization / ordering
/ confidence calculation all live inside `core/incident_response`, never
duplicated here. This mirrors `core.tools.mitre_tools.
MitreMappingResolutionTool`'s identical relationship to
`core.knowledge.mitre.lookup.MitreLookup` exactly.

Input stays **typed**, not dict-shaped (`core/tools` is explicitly allowed
to import `core/incident_response` directly — docs/dependency-rules.md rule
5b, mirroring rule 5's existing `core/knowledge` exception for
`mitre_tools.py`) — there is no "why input stays dict-shaped" boundary to
observe here (contrast `owasp_tools.py`'s docstring, which documents exactly
that boundary for `core.owasp_security`).
"""

from __future__ import annotations

from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

from core.incident_response.inputs import IncidentInputFinding
from core.incident_response.models import IncidentResponsePlan
from core.incident_response.response_plan_engine import ResponsePlanEngine
from core.tools.base import BaseTool

#: Default ceiling on findings accepted per generation call — mirrors
#: `core.incident_response.response_plan_engine.ResponsePlanEngine`'s own
#: default, kept in sync explicitly rather than importing a private constant.
DEFAULT_MAX_FINDINGS_PER_PLAN = 5_000


class IncidentResponsePlanGenerationInput(BaseModel):
    """A case's normalized, already-assessed findings — every field on each
    `IncidentInputFinding` is a value some other subsystem already computed;
    this tool performs no severity/risk/MITRE derivation of its own
    (constitution §1.9)."""

    model_config = ConfigDict(frozen=True)

    case_id: str
    findings: list[IncidentInputFinding] = Field(default_factory=list)
    skipped_record_count: int = Field(default=0, ge=0)


class IncidentResponsePlanGenerationOutput(BaseModel):
    model_config = ConfigDict(frozen=True)

    plan: IncidentResponsePlan


class IncidentResponsePlanGenerationTool(
    BaseTool[IncidentResponsePlanGenerationInput, IncidentResponsePlanGenerationOutput]
):
    """Deterministic, no-I/O — never retried (constitution §5/§4.8). Given
    the same input, always returns the same plan (modulo `plan_id`/
    `generated_at`, which are identity/provenance fields, not planning
    output — see `core.incident_response.response_plan_engine.
    ResponsePlanEngine`'s docstring)."""

    name: ClassVar[str] = "incident_response_plan_generation"
    description: ClassVar[str] = (
        "Generates a deterministic, NIST SP 800-61-aligned incident response plan from "
        "a case's already-assessed findings."
    )
    is_io_bound: ClassVar[bool] = False

    def __init__(self, *, max_findings_per_plan: int = DEFAULT_MAX_FINDINGS_PER_PLAN) -> None:
        super().__init__()
        self._engine = ResponsePlanEngine(max_findings_per_plan=max_findings_per_plan)

    def run(
        self, arguments: IncidentResponsePlanGenerationInput
    ) -> IncidentResponsePlanGenerationOutput:
        plan = self._engine.generate(
            case_id=arguments.case_id,
            findings=arguments.findings,
            skipped_record_count=arguments.skipped_record_count,
        )
        return IncidentResponsePlanGenerationOutput(plan=plan)
