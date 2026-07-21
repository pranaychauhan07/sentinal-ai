"""`ReportGenerationEngine` — the task's named pipeline orchestrator:

    Load Persisted Data (already done by the caller -> `ReportGenerationContext`)
        -> Generate Sections
        -> Assemble Report
        -> Validate Completeness
        -> Calculate Statistics
        -> build GeneratedReport

"Persist Report" / "Publish Report Events" / "Return Report" (the task's
last three named stages) are deliberately **not** this engine's job — those
are `core/services`/`core/db` concerns; this engine returns a plain
`GeneratedReport` value, mirroring
`core.incident_response.response_plan_engine.ResponsePlanEngine`'s
identical separation of concerns exactly.
"""

from __future__ import annotations

from core.reporting.audit import AuditAction, log_report_generation_audit_event, timed_execution
from core.reporting.completeness_validator import validate_completeness
from core.reporting.confidence_calculator import calculate_report_confidence
from core.reporting.exceptions import OversizedReportInputError, UnknownReportTypeError
from core.reporting.inputs import ReportGenerationContext
from core.reporting.metrics import ReportGenerationMetricsCollector
from core.reporting.models import GeneratedReport, ReportSection, ReportType
from core.reporting.section_builders import SECTION_BUILDERS
from core.reporting.section_registry import REPORT_TYPE_SECTIONS, default_title_for
from core.reporting.statistics_calculator import calculate_statistics

#: Ceiling on the combined size of every record collection a single
#: generation call accepts — the resource-exhaustion guard for a
#: pathologically large case (mirrors
#: `core.incident_response.response_plan_engine.ResponsePlanEngine`'s
#: `max_findings_per_plan` guard).
DEFAULT_MAX_RECORDS_PER_REPORT = 20_000


def _context_record_count(context: ReportGenerationContext) -> int:
    return (
        len(context.findings)
        + len(context.mitre_mappings)
        + len(context.iocs)
        + len(context.evidence_items)
        + len(context.thought_entries)
        + len(context.vulnerability_records)
        + len(context.linux_security_records)
        + len(context.linux_advisory_records)
        + len(context.owasp_web_records)
        + len(context.owasp_security_records)
    )


class ReportGenerationEngine:
    """Deterministic, no-I/O (constitution §5) — given the same
    `ReportGenerationContext`/`ReportType`, always returns the same
    `GeneratedReport` (modulo `report_id`/`generated_at`, which are
    identity/provenance fields, not generation output)."""

    def __init__(
        self,
        *,
        max_records_per_report: int = DEFAULT_MAX_RECORDS_PER_REPORT,
        metrics: ReportGenerationMetricsCollector | None = None,
    ) -> None:
        self._max_records_per_report = max_records_per_report
        self._metrics = metrics or ReportGenerationMetricsCollector()

    def generate(
        self, *, context: ReportGenerationContext, report_type: ReportType
    ) -> GeneratedReport:
        if report_type not in REPORT_TYPE_SECTIONS:
            raise UnknownReportTypeError(
                f"No section mapping registered for report type '{report_type.value}'.",
                details={"report_type": report_type.value},
            )

        record_count = _context_record_count(context)
        if record_count > self._max_records_per_report:
            log_report_generation_audit_event(
                action=AuditAction.OVERSIZED_REPORT_INPUT_REJECTED,
                case_id=context.case_id,
                detail=f"{record_count} records exceeds max {self._max_records_per_report}.",
            )
            raise OversizedReportInputError(
                f"{record_count} input records exceeds the configured maximum of "
                f"{self._max_records_per_report} for a single report generation.",
                details={"case_id": context.case_id, "record_count": record_count},
            )

        with timed_execution("generate_report") as timing:
            sections: list[ReportSection] = []
            for section_type in REPORT_TYPE_SECTIONS[report_type]:
                builder = SECTION_BUILDERS[section_type]
                section = builder(context)
                sections.append(section)
                if section.is_empty:
                    self._metrics.record_section_failed()
                    log_report_generation_audit_event(
                        action=AuditAction.SECTION_FAILED,
                        case_id=context.case_id,
                        section_type=section_type.value,
                        detail="Section generated with no data available.",
                    )
                else:
                    self._metrics.record_section_generated()
                    log_report_generation_audit_event(
                        action=AuditAction.SECTION_GENERATED,
                        case_id=context.case_id,
                        section_type=section_type.value,
                    )

            ordered_sections = tuple(sections)
            validation = validate_completeness(report_type, ordered_sections)
            statistics = calculate_statistics(context, ordered_sections, duration_ms=0.0)

        statistics = statistics.model_copy(update={"generation_duration_ms": timing["duration_ms"]})
        self._metrics.record_processing_time(timing["duration_ms"])
        confidence = calculate_report_confidence(context, ordered_sections, validation)

        degraded_reasons = list(validation.reasons)
        degraded = not validation.is_complete
        if degraded:
            log_report_generation_audit_event(
                action=AuditAction.REPORT_DEGRADED,
                case_id=context.case_id,
                detail="; ".join(degraded_reasons),
            )

        report = GeneratedReport(
            case_id=context.case_id,
            report_type=report_type,
            title=default_title_for(report_type),
            sections=ordered_sections,
            statistics=statistics,
            validation=validation,
            confidence=confidence,
            degraded=degraded,
            degraded_reasons=tuple(degraded_reasons),
        )
        self._metrics.record_report_generated()
        log_report_generation_audit_event(
            action=AuditAction.REPORT_GENERATED,
            case_id=context.case_id,
            detail=f"{len(ordered_sections)} section(s), report_type={report_type.value}.",
        )
        return report
