"""`calculate_report_confidence` — the case-level rollup
`GeneratedReport.confidence` is built from. Pure, deterministic
(constitution §1.9), mirroring
`core.incident_response.confidence_calculator.calculate_plan_confidence`'s
identical shape: a report built from a case where many input records were
malformed/skipped is genuinely less trustworthy, and that must be visible in
the number, not just a log line.
"""

from __future__ import annotations

from core.reporting.inputs import ReportGenerationContext
from core.reporting.models import ReportSection, ReportValidationResult


def calculate_report_confidence(
    context: ReportGenerationContext,
    sections: tuple[ReportSection, ...],
    validation: ReportValidationResult,
) -> float:
    if not sections:
        return 0.0
    non_empty_fraction = sum(1 for s in sections if not s.is_empty) / len(sections)

    considered_record_count = (
        len(context.findings)
        + len(context.mitre_mappings)
        + len(context.iocs)
        + len(context.vulnerability_records)
        + len(context.linux_security_records)
        + len(context.linux_advisory_records)
        + len(context.owasp_web_records)
        + len(context.owasp_security_records)
    )
    total = considered_record_count + context.skipped_record_count
    clean_fraction = considered_record_count / total if total else 1.0

    completeness_penalty = 1.0 if validation.is_complete else 0.75
    confidence = non_empty_fraction * clean_fraction * completeness_penalty
    return round(min(max(confidence, 0.0), 1.0), 4)
