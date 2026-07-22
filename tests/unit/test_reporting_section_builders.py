"""Unit tests for core/reporting/section_builders.py — each builder in
isolation, including malformed-entry skip-don't-crash behavior.
"""

from __future__ import annotations

import pytest

from core.reporting.inputs import ReportGenerationContext
from core.reporting.section_builders import (
    build_appendix,
    build_case_overview,
    build_executive_summary,
    build_findings,
    build_incident_response_actions,
    build_ioc_summary,
    build_mitre_mapping,
    build_recommendations,
    build_risk_assessment,
)

pytestmark = pytest.mark.unit


def test_empty_context_produces_empty_sections() -> None:
    context = ReportGenerationContext(case_id="c1")
    assert build_findings(context).is_empty is True
    assert build_ioc_summary(context).is_empty is True
    assert build_mitre_mapping(context).is_empty is True


def test_case_overview_reports_counts() -> None:
    context = ReportGenerationContext(
        case_id="c1",
        findings=({"finding_id": "f1", "title": "x", "severity": "high"},),
        evidence_items=({"evidence_type": "ssh_auth", "record_count": 5},),
    )
    section = build_case_overview(context)
    assert section.content["finding_count"] == 1
    assert section.content["evidence_item_count"] == 1
    assert section.is_empty is False


def test_ioc_summary_includes_bounded_sorted_table_and_hash_subset() -> None:
    context = ReportGenerationContext(
        case_id="c1",
        iocs=(
            {
                "value": "203.0.113.5",
                "ioc_type": "ipv4",
                "severity": "high",
                "classification": "malicious",
                "composite_score": 40.0,
                "first_seen": "2026-01-01T00:00:00+00:00",
            },
            {
                "value": "a" * 64,
                "ioc_type": "sha256",
                "severity": "critical",
                "classification": "malicious",
                "composite_score": 90.0,
                "first_seen": "2026-01-02T00:00:00+00:00",
            },
        ),
    )
    section = build_ioc_summary(context)
    assert section.content["ioc_count"] == 2
    iocs = section.content["iocs"]
    assert isinstance(iocs, list)
    assert len(iocs) == 2
    # Sorted by composite_score descending — highest-risk indicator first.
    assert iocs[0]["value"] == "a" * 64
    hashes = section.content["hashes"]
    assert isinstance(hashes, list)
    assert len(hashes) == 1
    assert hashes[0]["ioc_type"] == "sha256"
    assert section.content["truncated_row_count"] == 0


def test_findings_aggregates_across_every_source() -> None:
    context = ReportGenerationContext(
        case_id="c1",
        findings=({"title": "brute force", "severity": "high", "risk_score": 70.0},),
        vulnerability_records=({"title": "RCE", "severity": "critical", "composite_score": 95.0},),
        owasp_web_records=(
            {"kind": "finding", "category": "xss", "severity": "medium"},
            {"kind": "summary", "overall_risk_level": "medium"},
        ),
    )
    section = build_findings(context)
    # finding + vulnerability + one owasp_web "finding"-kind entry (the
    # "summary"-kind entry is deliberately excluded).
    assert section.content["finding_count"] == 3
    assert section.content["highest_severity"] == "critical"


def test_findings_surfaces_evidence_summary_and_severity_rationale() -> None:
    """Explainability requirement: the report's Findings section must carry
    the real evidence/severity reasoning, not just a title/severity/score
    triad."""
    context = ReportGenerationContext(
        case_id="c1",
        findings=(
            {
                "title": "Brute Force (T1110): username 'admin'",
                "severity": "high",
                "risk_score": 70.0,
                "evidence_summary": "username 'admin', ipv4 '203.0.113.5'",
                "severity_rationale": "Base severity 'high' from...",
            },
        ),
    )
    section = build_findings(context)
    finding = section.content["findings"][0]
    assert finding["evidence_summary"] == "username 'admin', ipv4 '203.0.113.5'"
    assert finding["severity_rationale"] == "Base severity 'high' from..."


def test_findings_skips_malformed_entries_never_crashes() -> None:
    """`ReportGenerationContext`'s Pydantic validation already rejects a
    non-dict entry at construction time (the agent's `_dict_records` filters
    malformed entries before the context is ever built) — `model_construct`
    bypasses that validation here specifically to exercise the section
    builders' own defensive `isinstance` checks (constitution §1.7's
    "skip malformed, never crash" belt-and-suspenders)."""
    context = ReportGenerationContext.model_construct(
        case_id="c1",
        findings=({"title": "ok", "severity": "low"}, "not-a-dict"),
        mitre_mappings=(),
        iocs=(),
        evidence_items=(),
        thought_entries=(),
        vulnerability_records=(),
        linux_security_records=(),
        linux_advisory_records=(),
        owasp_web_records=(),
        owasp_security_records=(),
        incident_response_plan=None,
        skipped_record_count=0,
    )
    section = build_findings(context)
    assert section.content["finding_count"] == 1


def test_mitre_mapping_dedups_by_technique_and_aggregates_tactics() -> None:
    context = ReportGenerationContext(
        case_id="c1",
        mitre_mappings=(
            {"technique_id": "T1110", "tactic_ids": ["TA0006"], "confidence": 0.9},
            {"technique_id": "T1110", "tactic_ids": ["TA0006"], "confidence": 0.5},
            {"technique_id": "T1078", "tactic_ids": ["TA0001"], "confidence": 0.8},
        ),
    )
    section = build_mitre_mapping(context)
    assert section.content["technique_count"] == 2
    assert section.content["distinct_tactic_count"] == 2


def test_mitre_mapping_surfaces_rule_id_and_rationale() -> None:
    context = ReportGenerationContext(
        case_id="c1",
        mitre_mappings=(
            {
                "technique_id": "T1110",
                "tactic_ids": ["TA0006"],
                "confidence": 0.9,
                "rule_id": "R-T1110-brute-force",
                "rationale": "Matched 3 indicator(s): username='admin'.",
            },
        ),
    )
    section = build_mitre_mapping(context)
    technique = section.content["techniques"][0]
    assert technique["rule_id"] == "R-T1110-brute-force"
    assert "admin" in technique["rationale"]


def test_incident_response_actions_no_plan_reports_has_plan_false() -> None:
    context = ReportGenerationContext(case_id="c1")
    section = build_incident_response_actions(context)
    assert section.content["has_plan"] is False
    assert section.content["recommendation_count"] == 0


def test_incident_response_actions_with_plan() -> None:
    context = ReportGenerationContext(
        case_id="c1",
        incident_response_plan={
            "incident_severity": "high",
            "recommendations": [
                {
                    "action": {
                        "title": "Isolate host",
                        "category": "host_isolation",
                        "phase": "containment",
                    },
                    "priority": "p1_immediate",
                    "execution_order": 1,
                }
            ],
        },
    )
    section = build_incident_response_actions(context)
    assert section.content["has_plan"] is True
    assert section.content["recommendation_count"] == 1


def test_incident_response_actions_surfaces_severity_justification() -> None:
    context = ReportGenerationContext(
        case_id="c1",
        incident_response_plan={
            "incident_severity": "critical",
            "severity_justification": "Base severity 'high', escalated 1 level(s)...",
            "recommendations": [
                {
                    "action": {
                        "title": "Isolate host",
                        "category": "host_isolation",
                        "phase": "containment",
                    },
                    "priority": "p1_immediate",
                    "execution_order": 1,
                    "rationale": "Triggered by finding X.",
                }
            ],
        },
    )
    section = build_incident_response_actions(context)
    assert (
        section.content["severity_justification"] == "Base severity 'high', escalated 1 level(s)..."
    )
    assert section.content["recommendations"][0]["rationale"] == "Triggered by finding X."


def test_recommendations_deduplicates_across_sources() -> None:
    context = ReportGenerationContext(
        case_id="c1",
        linux_advisory_records=(
            {"kind": "hardening", "recommendation": "Disable root SSH login."},
        ),
        owasp_web_records=(
            {
                "kind": "finding",
                "category": "xss",
                "recommended_remediation": "Disable root SSH login.",
            },
        ),
    )
    section = build_recommendations(context)
    assert section.content["recommendation_count"] == 1


def test_risk_assessment_reports_highest_severity() -> None:
    context = ReportGenerationContext(
        case_id="c1",
        findings=({"severity": "low"},),
        vulnerability_records=({"severity": "critical"},),
    )
    section = build_risk_assessment(context)
    assert section.content["overall_risk_level"] == "critical"


def test_executive_summary_rolls_up_risk_and_finding_count() -> None:
    context = ReportGenerationContext(
        case_id="c1",
        findings=({"severity": "high", "risk_score": 50.0},),
    )
    section = build_executive_summary(context)
    assert section.content["overall_risk_level"] == "high"
    assert section.content["finding_count"] == 1


def test_appendix_reports_skipped_count_and_data_sources() -> None:
    context = ReportGenerationContext(
        case_id="c1", findings=({"title": "x"},), skipped_record_count=3
    )
    section = build_appendix(context)
    assert section.content["skipped_record_count"] == 3
    assert "findings" in section.content["data_sources"]
