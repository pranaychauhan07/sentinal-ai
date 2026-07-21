"""Pure, deterministic functions building each `ReportSectionType` from an
already-normalized `ReportGenerationContext` — no LLM reasoning anywhere
(task requirement), no re-derivation of any severity/score/mapping any
upstream subsystem already computed (constitution §1.9). Every builder is
skip-on-malformed, never fatal to the whole report (constitution §1.7).
"""

from __future__ import annotations

from collections.abc import Callable

from core.reporting.inputs import ReportGenerationContext
from core.reporting.models import ReportSection, ReportSectionType

_SectionBuilder = Callable[[ReportGenerationContext], ReportSection]

#: Deterministic severity rank shared by every section builder below — a
#: local, string-keyed table (never importing a sibling leaf's severity enum
#: sideways, constitution §3) since every upstream subsystem's severity
#: values already collapse onto this same five-value vocabulary
#: (`info`/`low`/`medium`/`high`/`critical`).
_SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def _rank(severity: object) -> int:
    return _SEVERITY_RANK.get(str(severity).lower(), 0)


def _as_list(value: object) -> list[object]:
    """Narrows a `dict[str, object].get(...)` result to a plain list — the
    dict-shaped `*_records`/plan payloads this package aggregates carry no
    static type guarantee on nested values, so every list-shaped field is
    read defensively (constitution §1.7: skip malformed, never crash)."""
    if isinstance(value, list | tuple):
        return list(value)
    return []


def _highest_severity(severities: list[str]) -> str:
    if not severities:
        return "info"
    return max(severities, key=_rank)


def _section(
    section_type: ReportSectionType, title: str, content: dict[str, object], *, is_empty: bool
) -> ReportSection:
    return ReportSection(section_type=section_type, title=title, content=content, is_empty=is_empty)


def build_case_overview(context: ReportGenerationContext) -> ReportSection:
    evidence_item_count = len(context.evidence_items)
    finding_count = len(context.findings)
    has_plan = context.incident_response_plan is not None
    return _section(
        ReportSectionType.CASE_OVERVIEW,
        "Case Overview",
        {
            "case_id": context.case_id,
            "evidence_item_count": evidence_item_count,
            "finding_count": finding_count,
            "has_incident_response_plan": has_plan,
        },
        is_empty=evidence_item_count == 0 and finding_count == 0 and not has_plan,
    )


def build_investigation_timeline(context: ReportGenerationContext) -> ReportSection:
    entries = [
        {
            "agent_name": entry.get("agent_name", ""),
            "thought": entry.get("thought", ""),
            "confidence": entry.get("confidence", 0.0),
            "created_at": entry.get("created_at", ""),
        }
        for entry in context.thought_entries
        if isinstance(entry, dict)
    ]
    return _section(
        ReportSectionType.INVESTIGATION_TIMELINE,
        "Investigation Timeline",
        {"entry_count": len(entries), "entries": entries},
        is_empty=not entries,
    )


def build_evidence_summary(context: ReportGenerationContext) -> ReportSection:
    items = [
        {
            "evidence_type": str(item.get("evidence_type", "")),
            "record_count": item.get("record_count", 0),
        }
        for item in context.evidence_items
        if isinstance(item, dict)
    ]
    distinct_types = sorted({str(item["evidence_type"]) for item in items if item["evidence_type"]})
    return _section(
        ReportSectionType.EVIDENCE_SUMMARY,
        "Evidence Summary",
        {"evidence_item_count": len(items), "distinct_evidence_types": distinct_types},
        is_empty=not items,
    )


def build_ioc_summary(context: ReportGenerationContext) -> ReportSection:
    by_type: dict[str, int] = {}
    for ioc in context.iocs:
        if not isinstance(ioc, dict):
            continue
        ioc_type = str(ioc.get("ioc_type", "unknown"))
        by_type[ioc_type] = by_type.get(ioc_type, 0) + 1
    return _section(
        ReportSectionType.IOC_SUMMARY,
        "IOC Summary",
        {"ioc_count": len(context.iocs), "iocs_by_type": by_type},
        is_empty=not context.iocs,
    )


def build_threat_intelligence_summary(context: ReportGenerationContext) -> ReportSection:
    distinct_techniques = {
        str(m["technique_id"])
        for m in context.mitre_mappings
        if isinstance(m, dict) and m.get("technique_id")
    }
    by_type: dict[str, int] = {}
    for ioc in context.iocs:
        if not isinstance(ioc, dict):
            continue
        ioc_type = str(ioc.get("ioc_type", "unknown"))
        by_type[ioc_type] = by_type.get(ioc_type, 0) + 1
    return _section(
        ReportSectionType.THREAT_INTELLIGENCE_SUMMARY,
        "Threat Intelligence Summary",
        {
            "distinct_mitre_technique_count": len(distinct_techniques),
            "ioc_count": len(context.iocs),
            "iocs_by_type": by_type,
        },
        is_empty=not distinct_techniques and not context.iocs,
    )


def build_mitre_mapping(context: ReportGenerationContext) -> ReportSection:
    techniques: dict[str, dict[str, object]] = {}
    distinct_tactics: set[str] = set()
    for mapping in context.mitre_mappings:
        if not isinstance(mapping, dict) or not mapping.get("technique_id"):
            continue
        technique_id = str(mapping["technique_id"])
        tactic_ids = _as_list(mapping.get("tactic_ids"))
        techniques.setdefault(
            technique_id,
            {
                "technique_id": technique_id,
                "confidence": mapping.get("confidence", 0.0),
                "tactic_ids": tactic_ids,
                # Explainability requirement: which rule fired and why —
                # read straight through from the persisted `MitreMapping`,
                # never re-derived (constitution §1.9).
                "rule_id": mapping.get("rule_id", ""),
                "rationale": mapping.get("rationale", ""),
            },
        )
        distinct_tactics.update(str(t) for t in tactic_ids)
    return _section(
        ReportSectionType.MITRE_MAPPING,
        "MITRE ATT&CK Mapping",
        {
            "technique_count": len(techniques),
            "distinct_tactic_count": len(distinct_tactics),
            "techniques": sorted(techniques.values(), key=lambda t: str(t["technique_id"])),
        },
        is_empty=not techniques,
    )


def build_findings(context: ReportGenerationContext) -> ReportSection:
    finding_summaries: list[dict[str, object]] = []
    for finding in context.findings:
        if not isinstance(finding, dict):
            continue
        finding_summaries.append(
            {
                "source": "finding",
                "title": finding.get("title", ""),
                "severity": finding.get("severity", "info"),
                "risk_score": finding.get("risk_score", 0.0),
                # Explainability requirement: real evidence/severity
                # reasoning, read straight through (never re-derived).
                "evidence_summary": finding.get("evidence_summary", ""),
                "severity_rationale": finding.get("severity_rationale", ""),
            }
        )
    for record in context.vulnerability_records:
        if not isinstance(record, dict):
            continue
        finding_summaries.append(
            {
                "source": "vulnerability_assessment",
                "title": record.get("title", ""),
                "severity": record.get("severity", "info"),
                "risk_score": record.get("composite_score", 0.0),
            }
        )
    for record in context.linux_security_records:
        if not isinstance(record, dict):
            continue
        finding_summaries.append(
            {
                "source": "linux_security_threat_hunting",
                "title": record.get("title", ""),
                "severity": record.get("severity", "info"),
                "risk_score": record.get("composite_score", 0.0),
            }
        )
    for record in context.owasp_web_records:
        if not isinstance(record, dict) or record.get("kind") != "finding":
            continue
        finding_summaries.append(
            {
                "source": "owasp_web_security",
                "title": record.get("explanation", record.get("category", "")),
                "severity": record.get("severity", "info"),
                "risk_score": 0.0,
            }
        )
    for record in context.owasp_security_records:
        if not isinstance(record, dict) or record.get("kind") != "finding":
            continue
        finding_summaries.append(
            {
                "source": "owasp_source_code_review",
                "title": record.get("explanation", record.get("category", "")),
                "severity": record.get("severity", "info"),
                "risk_score": 0.0,
            }
        )
    severities = [str(f["severity"]) for f in finding_summaries]
    return _section(
        ReportSectionType.FINDINGS,
        "Findings",
        {
            "finding_count": len(finding_summaries),
            "highest_severity": _highest_severity(severities),
            "findings": finding_summaries,
        },
        is_empty=not finding_summaries,
    )


def build_incident_response_actions(context: ReportGenerationContext) -> ReportSection:
    plan = context.incident_response_plan
    if not plan:
        return _section(
            ReportSectionType.INCIDENT_RESPONSE_ACTIONS,
            "Incident Response Actions",
            {"has_plan": False, "recommendation_count": 0, "recommendations": []},
            is_empty=True,
        )
    recommendations: list[dict[str, object]] = []
    for r in _as_list(plan.get("recommendations")):
        if not isinstance(r, dict):
            continue
        action = r.get("action")
        action_dict = action if isinstance(action, dict) else {}
        recommendations.append(
            {
                "title": action_dict.get("title", ""),
                "category": action_dict.get("category", ""),
                "phase": action_dict.get("phase", ""),
                "priority": r.get("priority", ""),
                "execution_order": r.get("execution_order", 0),
                "rationale": r.get("rationale", ""),
            }
        )
    return _section(
        ReportSectionType.INCIDENT_RESPONSE_ACTIONS,
        "Incident Response Actions",
        {
            "has_plan": True,
            "incident_severity": plan.get("incident_severity", "info"),
            # Explainability requirement: "if escalation to Critical
            # occurs, provide deterministic justification" — read straight
            # through from the persisted `IncidentResponsePlan.
            # severity_justification`, never re-derived.
            "severity_justification": plan.get("severity_justification", ""),
            "recommendation_count": len(recommendations),
            "recommendations": recommendations,
        },
        is_empty=not recommendations,
    )


def build_risk_assessment(context: ReportGenerationContext) -> ReportSection:
    severities: list[str] = []
    severities.extend(
        str(f.get("severity", "info")) for f in context.findings if isinstance(f, dict)
    )
    severities.extend(
        str(r.get("severity", "info")) for r in context.vulnerability_records if isinstance(r, dict)
    )
    severities.extend(
        str(r.get("severity", "info"))
        for r in context.linux_security_records
        if isinstance(r, dict)
    )
    for record in (*context.owasp_web_records, *context.owasp_security_records):
        if isinstance(record, dict) and record.get("kind") == "finding":
            severities.append(str(record.get("severity", "info")))
    plan = context.incident_response_plan
    if plan:
        severities.append(str(plan.get("incident_severity", "info")))

    by_severity: dict[str, int] = {}
    for severity in severities:
        by_severity[severity] = by_severity.get(severity, 0) + 1

    return _section(
        ReportSectionType.RISK_ASSESSMENT,
        "Risk Assessment",
        {
            "overall_risk_level": _highest_severity(severities),
            "severity_breakdown": by_severity,
            "total_risk_signals": len(severities),
        },
        is_empty=not severities,
    )


def build_recommendations(context: ReportGenerationContext) -> ReportSection:
    recommendations: list[str] = []
    for record in context.linux_advisory_records:
        if isinstance(record, dict) and record.get("kind") == "hardening":
            text = str(record.get("recommendation", "")).strip()
            if text:
                recommendations.append(text)
    for record in (*context.owasp_web_records, *context.owasp_security_records):
        if isinstance(record, dict) and record.get("kind") == "finding":
            text = str(record.get("recommended_remediation", "")).strip()
            if text:
                recommendations.append(text)
    plan = context.incident_response_plan
    if plan:
        for r in _as_list(plan.get("recommendations")):
            if not isinstance(r, dict):
                continue
            action = r.get("action")
            action_dict = action if isinstance(action, dict) else {}
            description = str(action_dict.get("description", "")).strip()
            if description:
                recommendations.append(description)
        recommendations.extend(str(lesson) for lesson in _as_list(plan.get("lessons_learned")))

    #: Deduplicated, order-preserving — the same recommendation text
    #: surfacing from two sources is reported once, not twice.
    seen: set[str] = set()
    deduplicated: list[str] = []
    for text in recommendations:
        if text not in seen:
            seen.add(text)
            deduplicated.append(text)

    return _section(
        ReportSectionType.RECOMMENDATIONS,
        "Recommendations",
        {"recommendation_count": len(deduplicated), "recommendations": deduplicated},
        is_empty=not deduplicated,
    )


def build_executive_summary(context: ReportGenerationContext) -> ReportSection:
    risk_section = build_risk_assessment(context)
    findings_section = build_findings(context)
    ioc_count = len(context.iocs)
    incident_response_recommendation_count = (
        len(_as_list(context.incident_response_plan.get("recommendations")))
        if context.incident_response_plan
        else 0
    )
    raw_finding_count = findings_section.content["finding_count"]
    finding_count = raw_finding_count if isinstance(raw_finding_count, int) else 0
    return _section(
        ReportSectionType.EXECUTIVE_SUMMARY,
        "Executive Summary",
        {
            "overall_risk_level": risk_section.content["overall_risk_level"],
            "finding_count": finding_count,
            "ioc_count": ioc_count,
            "incident_response_recommendation_count": incident_response_recommendation_count,
        },
        is_empty=finding_count == 0
        and ioc_count == 0
        and incident_response_recommendation_count == 0,
    )


def build_appendix(context: ReportGenerationContext) -> ReportSection:
    data_sources = sorted(
        name
        for name, present in (
            ("findings", bool(context.findings)),
            ("mitre_mappings", bool(context.mitre_mappings)),
            ("iocs", bool(context.iocs)),
            ("vulnerability_records", bool(context.vulnerability_records)),
            ("linux_security_records", bool(context.linux_security_records)),
            ("linux_advisory_records", bool(context.linux_advisory_records)),
            ("owasp_web_records", bool(context.owasp_web_records)),
            ("owasp_security_records", bool(context.owasp_security_records)),
            ("incident_response_plan", context.incident_response_plan is not None),
        )
        if present
    )
    return _section(
        ReportSectionType.APPENDIX,
        "Appendix",
        {"skipped_record_count": context.skipped_record_count, "data_sources": data_sources},
        is_empty=not data_sources,
    )


#: One builder per `ReportSectionType` — `report_engine.py` dispatches
#: through this table rather than an `if`/`elif` chain, so adding a section
#: type later means adding one entry here, matching every other leaf
#: package's registry-table convention.
SECTION_BUILDERS: dict[ReportSectionType, _SectionBuilder] = {
    ReportSectionType.EXECUTIVE_SUMMARY: build_executive_summary,
    ReportSectionType.CASE_OVERVIEW: build_case_overview,
    ReportSectionType.INVESTIGATION_TIMELINE: build_investigation_timeline,
    ReportSectionType.EVIDENCE_SUMMARY: build_evidence_summary,
    ReportSectionType.IOC_SUMMARY: build_ioc_summary,
    ReportSectionType.THREAT_INTELLIGENCE_SUMMARY: build_threat_intelligence_summary,
    ReportSectionType.MITRE_MAPPING: build_mitre_mapping,
    ReportSectionType.FINDINGS: build_findings,
    ReportSectionType.INCIDENT_RESPONSE_ACTIONS: build_incident_response_actions,
    ReportSectionType.RISK_ASSESSMENT: build_risk_assessment,
    ReportSectionType.RECOMMENDATIONS: build_recommendations,
    ReportSectionType.APPENDIX: build_appendix,
}
