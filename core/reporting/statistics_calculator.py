"""`calculate_statistics` — the task's named "Calculate Statistics" pipeline
stage. Pure, deterministic (constitution §1.9): every count comes directly
from `ReportGenerationContext`'s already-normalized fields or the assembled
`sections` tuple, never recomputed by a caller.
"""

from __future__ import annotations

from core.reporting.inputs import ReportGenerationContext
from core.reporting.models import ReportSection, ReportStatistics


def calculate_statistics(
    context: ReportGenerationContext,
    sections: tuple[ReportSection, ...],
    *,
    duration_ms: float = 0.0,
) -> ReportStatistics:
    distinct_techniques = {
        str(m["technique_id"])
        for m in context.mitre_mappings
        if isinstance(m, dict) and m.get("technique_id")
    }
    owasp_web_finding_count = sum(
        1
        for record in context.owasp_web_records
        if isinstance(record, dict) and record.get("kind") == "finding"
    )
    owasp_security_finding_count = sum(
        1
        for record in context.owasp_security_records
        if isinstance(record, dict) and record.get("kind") == "finding"
    )
    linux_advisory_count = sum(
        1
        for record in context.linux_advisory_records
        if isinstance(record, dict) and record.get("kind") in ("command", "permission")
    )
    incident_response_recommendation_count = 0
    if context.incident_response_plan is not None:
        recommendations = context.incident_response_plan.get("recommendations")
        if isinstance(recommendations, list | tuple):
            incident_response_recommendation_count = len(recommendations)

    return ReportStatistics(
        finding_count=len(context.findings),
        evidence_count=len(context.evidence_items),
        ioc_count=len(context.iocs),
        mitre_technique_count=len(distinct_techniques),
        vulnerability_count=len(context.vulnerability_records),
        linux_security_finding_count=len(context.linux_security_records),
        linux_advisory_count=linux_advisory_count,
        owasp_web_finding_count=owasp_web_finding_count,
        owasp_security_finding_count=owasp_security_finding_count,
        incident_response_recommendation_count=incident_response_recommendation_count,
        sections_generated_count=len(sections),
        sections_empty_count=sum(1 for section in sections if section.is_empty),
        skipped_record_count=context.skipped_record_count,
        generation_duration_ms=round(duration_ms, 3),
    )
