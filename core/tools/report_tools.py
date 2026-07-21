"""``ReportGenerationTool`` — blueprint's exact named `report_tools.py`: the
Report Generator Agent's deterministic report-assembly tool.

Mirrors `core.tools.ir_tools.IncidentResponsePlanGenerationTool`'s identical
relationship to `core.incident_response.response_plan_engine.
ResponsePlanEngine` exactly: this tool's `run()` is a thin wrapper around
`core.reporting.report_engine.ReportGenerationEngine` — section generation,
completeness validation, statistics, and confidence calculation all live
inside `core/reporting`, never duplicated here.

Input stays **typed**, not dict-shaped (`core/tools` is explicitly allowed
to import `core/reporting` directly — docs/dependency-rules.md rule 5c,
mirroring rule 5b's identical `core/incident_response` exception for
`ir_tools.py` — docs/adr/0024-report-generator-agent.md).
"""

from __future__ import annotations

from typing import ClassVar

from pydantic import BaseModel, ConfigDict

from core.reporting.inputs import ReportGenerationContext
from core.reporting.models import GeneratedReport, ReportType
from core.reporting.report_engine import ReportGenerationEngine
from core.tools.base import BaseTool

#: Default ceiling on combined input record size per generation call —
#: mirrors `core.reporting.report_engine.ReportGenerationEngine`'s own
#: default, kept in sync explicitly rather than importing a private constant.
DEFAULT_MAX_RECORDS_PER_REPORT = 20_000


class ReportGenerationInput(BaseModel):
    """A case's normalized, already-computed data plus the requested
    `ReportType` — every field on `context` is a value some other subsystem
    already computed; this tool performs no severity/risk/MITRE/confidence
    derivation of its own (constitution §1.9)."""

    model_config = ConfigDict(frozen=True)

    context: ReportGenerationContext
    report_type: ReportType = ReportType.TECHNICAL_INVESTIGATION


class ReportGenerationOutput(BaseModel):
    model_config = ConfigDict(frozen=True)

    report: GeneratedReport


class ReportGenerationTool(BaseTool[ReportGenerationInput, ReportGenerationOutput]):
    """Deterministic, no-I/O — never retried (constitution §5/§4.8). Given
    the same input, always returns the same report (modulo `report_id`/
    `generated_at`, which are identity/provenance fields, not generation
    output — see `core.reporting.report_engine.ReportGenerationEngine`'s
    docstring)."""

    name: ClassVar[str] = "report_generation"
    description: ClassVar[str] = (
        "Generates a deterministic, strongly-typed investigation report from a case's "
        "already-computed findings, IOCs, MITRE mappings, and incident response plan."
    )
    is_io_bound: ClassVar[bool] = False

    def __init__(self, *, max_records_per_report: int = DEFAULT_MAX_RECORDS_PER_REPORT) -> None:
        super().__init__()
        self._engine = ReportGenerationEngine(max_records_per_report=max_records_per_report)

    def run(self, arguments: ReportGenerationInput) -> ReportGenerationOutput:
        report = self._engine.generate(context=arguments.context, report_type=arguments.report_type)
        return ReportGenerationOutput(report=report)
