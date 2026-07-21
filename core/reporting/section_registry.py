"""`REPORT_TYPE_SECTIONS` — the static, single source of truth for which
sections each of the task's eight named report types includes. A small,
package-internal lookup table (constitution §5's "leaves never call up" +
docs/dependency-rules.md rule 5: no reference-data dependency big enough to
warrant living in `core/knowledge` — the identical "small enough to live
inside the package" reasoning `core/owasp_security`/`core/incident_response`
already established).
"""

from __future__ import annotations

from core.reporting.models import ReportSectionType, ReportType

_TECHNICAL_INVESTIGATION_SECTIONS: tuple[ReportSectionType, ...] = (
    ReportSectionType.CASE_OVERVIEW,
    ReportSectionType.INVESTIGATION_TIMELINE,
    ReportSectionType.EVIDENCE_SUMMARY,
    ReportSectionType.FINDINGS,
    ReportSectionType.MITRE_MAPPING,
    ReportSectionType.INCIDENT_RESPONSE_ACTIONS,
    ReportSectionType.RISK_ASSESSMENT,
    ReportSectionType.RECOMMENDATIONS,
    ReportSectionType.APPENDIX,
)

#: Which `ReportSectionType`s each `ReportType` requires — exhaustive over
#: every `ReportType` member (enforced by a unit test iterating the enum).
REPORT_TYPE_SECTIONS: dict[ReportType, tuple[ReportSectionType, ...]] = {
    ReportType.EXECUTIVE: (
        ReportSectionType.EXECUTIVE_SUMMARY,
        ReportSectionType.CASE_OVERVIEW,
        ReportSectionType.RISK_ASSESSMENT,
        ReportSectionType.RECOMMENDATIONS,
    ),
    #: `MODULE` is a legacy, unused value (docs/adr/0024) — mapped to the
    #: same comprehensive section set as `TECHNICAL_INVESTIGATION` so it
    #: never becomes a dead end if ever requested.
    ReportType.MODULE: _TECHNICAL_INVESTIGATION_SECTIONS,
    ReportType.TECHNICAL_INVESTIGATION: _TECHNICAL_INVESTIGATION_SECTIONS,
    ReportType.INCIDENT_RESPONSE: (
        ReportSectionType.CASE_OVERVIEW,
        ReportSectionType.FINDINGS,
        ReportSectionType.INCIDENT_RESPONSE_ACTIONS,
        ReportSectionType.RISK_ASSESSMENT,
        ReportSectionType.RECOMMENDATIONS,
        ReportSectionType.APPENDIX,
    ),
    ReportType.IOC_SUMMARY: (
        ReportSectionType.CASE_OVERVIEW,
        ReportSectionType.IOC_SUMMARY,
        ReportSectionType.APPENDIX,
    ),
    ReportType.MITRE_ATTACK: (
        ReportSectionType.CASE_OVERVIEW,
        ReportSectionType.MITRE_MAPPING,
        ReportSectionType.APPENDIX,
    ),
    ReportType.TIMELINE: (
        ReportSectionType.CASE_OVERVIEW,
        ReportSectionType.INVESTIGATION_TIMELINE,
        ReportSectionType.APPENDIX,
    ),
    ReportType.THREAT_INTELLIGENCE: (
        ReportSectionType.CASE_OVERVIEW,
        ReportSectionType.THREAT_INTELLIGENCE_SUMMARY,
        ReportSectionType.IOC_SUMMARY,
        ReportSectionType.APPENDIX,
    ),
    ReportType.EVIDENCE: (
        ReportSectionType.CASE_OVERVIEW,
        ReportSectionType.EVIDENCE_SUMMARY,
        ReportSectionType.APPENDIX,
    ),
}


def default_title_for(report_type: ReportType) -> str:
    """Deterministic, human-readable default report title — never
    LLM-generated (task requirement: "no LLM-generated reasoning")."""
    titles: dict[ReportType, str] = {
        ReportType.EXECUTIVE: "Executive Summary Report",
        ReportType.MODULE: "Technical Investigation Report",
        ReportType.TECHNICAL_INVESTIGATION: "Technical Investigation Report",
        ReportType.INCIDENT_RESPONSE: "Incident Response Report",
        ReportType.IOC_SUMMARY: "IOC Summary Report",
        ReportType.MITRE_ATTACK: "MITRE ATT&CK Report",
        ReportType.TIMELINE: "Timeline Report",
        ReportType.THREAT_INTELLIGENCE: "Threat Intelligence Report",
        ReportType.EVIDENCE: "Evidence Report",
    }
    return titles[report_type]
