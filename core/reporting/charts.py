"""Plotly Visualization Engine — the task's named "Plotly Visualization
Engine" / "Visualizations" component.

One pure function per named chart type, each a deterministic function of an
already-generated `GeneratedReport` (constitution §1.9: no re-derivation of
any severity/score/mapping — every number plotted here already exists on
`report.statistics` or a `report.section(...)`'s `content`, this module only
visualizes it). Every function degrades gracefully to an annotated "no data
available" empty figure rather than raising when its source section is
missing/empty (constitution §1.7) — a report with sparse evidence still
renders, it just shows fewer/emptier charts, exactly like `GeneratedReport`
itself already tolerates degraded input.
"""

from __future__ import annotations

from collections.abc import Callable

import plotly.graph_objects as go

from core.reporting.models import GeneratedReport, ReportSectionType

_ChartBuilder = Callable[[GeneratedReport], go.Figure]

#: Shared, theme-independent categorical palette for severity levels —
#: kept here (not in `theme.py`) since it's a data-semantic mapping
#: (severity -> color), not a brand/style choice a custom theme should
#: override.
_SEVERITY_COLORS: dict[str, str] = {
    "critical": "#da3633",
    "high": "#d29922",
    "medium": "#9a6700",
    "low": "#316dca",
    "info": "#57606a",
}
_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _empty_figure(title: str, message: str = "No data available") -> go.Figure:
    figure = go.Figure()
    figure.update_layout(
        title=title,
        annotations=[
            {
                "text": message,
                "xref": "paper",
                "yref": "paper",
                "x": 0.5,
                "y": 0.5,
                "showarrow": False,
                "font": {"size": 16},
            }
        ],
        xaxis={"visible": False},
        yaxis={"visible": False},
    )
    return figure


def _safe_int(value: object, *, default: int = 0) -> int:
    """`ReportSection.content` values carry no static type guarantee
    (constitution §1.7, "skip malformed, never crash") — a non-numeric
    value degrades to `default` rather than raising `TypeError` out of a
    chart builder."""
    if isinstance(value, int | float):
        return int(value)
    return default


def _section_content(report: GeneratedReport, section_type: ReportSectionType) -> dict[str, object]:
    section = report.section(section_type)
    if section is None or section.is_empty:
        return {}
    return section.content


def severity_distribution_chart(report: GeneratedReport) -> go.Figure:
    """Findings/records grouped by severity — Risk Assessment section's
    `severity_breakdown`."""
    content = _section_content(report, ReportSectionType.RISK_ASSESSMENT)
    breakdown = content.get("severity_breakdown")
    if not isinstance(breakdown, dict) or not breakdown:
        return _empty_figure("Severity Distribution")
    labels = [s for s in _SEVERITY_ORDER if s in breakdown]
    labels += sorted(k for k in breakdown if k not in _SEVERITY_ORDER)
    values = [breakdown[label] for label in labels]
    colors = [_SEVERITY_COLORS.get(label, "#8b949e") for label in labels]
    figure = go.Figure(
        data=[go.Pie(labels=labels, values=values, marker={"colors": colors}, hole=0.35)]
    )
    figure.update_layout(title="Severity Distribution")
    return figure


def risk_trend_chart(report: GeneratedReport) -> go.Figure:
    """Confidence-over-time within this run's Investigation Timeline —
    a single-case, single-run proxy for "risk trend" (this pipeline has no
    cross-case historical trend data; that is the Memory Agent's domain,
    out of this framework's scope, disclosed here rather than silently
    faked)."""
    content = _section_content(report, ReportSectionType.INVESTIGATION_TIMELINE)
    entries = content.get("entries")
    if not isinstance(entries, list) or not entries:
        return _empty_figure("Risk Trend (Investigation Confidence Over Time)")
    x = [str(e.get("created_at", "")) for e in entries if isinstance(e, dict)]
    y = [float(e.get("confidence", 0.0) or 0.0) for e in entries if isinstance(e, dict)]
    figure = go.Figure(data=[go.Scatter(x=x, y=y, mode="lines+markers")])
    figure.update_layout(
        title="Risk Trend (Investigation Confidence Over Time)",
        xaxis_title="Time",
        yaxis_title="Confidence",
        yaxis={"range": [0, 1]},
    )
    return figure


def timeline_chart(report: GeneratedReport) -> go.Figure:
    """Chronological reconstruction of investigation events — blueprint
    §13's Threat Timeline, rendered from the same Investigation Timeline
    section as `risk_trend_chart` but as a per-agent event scatter rather
    than a confidence line."""
    content = _section_content(report, ReportSectionType.INVESTIGATION_TIMELINE)
    entries = content.get("entries")
    if not isinstance(entries, list) or not entries:
        return _empty_figure("Investigation Timeline")
    x = [str(e.get("created_at", "")) for e in entries if isinstance(e, dict)]
    agents = [str(e.get("agent_name", "unknown")) for e in entries if isinstance(e, dict)]
    figure = go.Figure(
        data=[
            go.Scatter(
                x=x,
                y=agents,
                mode="markers",
                marker={"size": 10},
                text=[str(e.get("thought", "")) for e in entries if isinstance(e, dict)],
            )
        ]
    )
    figure.update_layout(title="Investigation Timeline", xaxis_title="Time", yaxis_title="Agent")
    return figure


def mitre_heatmap_chart(report: GeneratedReport) -> go.Figure:
    """ATT&CK matrix-style tactic x technique coverage heatmap — MITRE
    Mapping section's `techniques` (each already carrying its resolved
    `tactic_ids`)."""
    content = _section_content(report, ReportSectionType.MITRE_MAPPING)
    techniques = content.get("techniques")
    if not isinstance(techniques, list) or not techniques:
        return _empty_figure("MITRE ATT&CK Coverage Heatmap")
    tactic_ids: list[str] = sorted(
        {
            str(t)
            for entry in techniques
            if isinstance(entry, dict)
            for t in entry.get("tactic_ids", [])
        }
    )
    technique_ids = sorted(
        {str(entry["technique_id"]) for entry in techniques if isinstance(entry, dict)}
    )
    if not tactic_ids or not technique_ids:
        return _empty_figure("MITRE ATT&CK Coverage Heatmap")
    z = [
        [
            1
            if any(
                str(e.get("technique_id")) == technique_id and tactic_id in e.get("tactic_ids", [])
                for e in techniques
                if isinstance(e, dict)
            )
            else 0
            for technique_id in technique_ids
        ]
        for tactic_id in tactic_ids
    ]
    figure = go.Figure(
        data=[go.Heatmap(z=z, x=technique_ids, y=tactic_ids, colorscale="Reds", showscale=False)]
    )
    figure.update_layout(
        title="MITRE ATT&CK Coverage Heatmap", xaxis_title="Technique", yaxis_title="Tactic"
    )
    return figure


def ioc_category_chart(report: GeneratedReport) -> go.Figure:
    """IOC counts by type — IOC Summary section's `iocs_by_type`."""
    content = _section_content(report, ReportSectionType.IOC_SUMMARY)
    by_type = content.get("iocs_by_type")
    if not isinstance(by_type, dict) or not by_type:
        return _empty_figure("IOC Categories")
    labels = sorted(by_type)
    values = [by_type[label] for label in labels]
    figure = go.Figure(data=[go.Bar(x=labels, y=values)])
    figure.update_layout(title="IOC Categories", xaxis_title="IOC Type", yaxis_title="Count")
    return figure


def threat_intelligence_sources_chart(report: GeneratedReport) -> go.Figure:
    """Threat Intelligence Summary section's aggregate counts (distinct
    MITRE techniques observed, total IOCs) as a comparison bar chart —
    "sources" in the sense of which intelligence dimensions this case's
    evidence contributed to, since this pipeline has no external
    per-feed-source attribution (blueprint §17's future STIX/TAXII feed
    integration would add that dimension; disclosed, not faked)."""
    content = _section_content(report, ReportSectionType.THREAT_INTELLIGENCE_SUMMARY)
    if not content:
        return _empty_figure("Threat Intelligence Sources")
    labels = ["IOCs", "Distinct MITRE Techniques"]
    values = [
        _safe_int(content.get("ioc_count")),
        _safe_int(content.get("distinct_mitre_technique_count")),
    ]
    figure = go.Figure(data=[go.Bar(x=labels, y=values)])
    figure.update_layout(title="Threat Intelligence Sources", yaxis_title="Count")
    return figure


def finding_distribution_chart(report: GeneratedReport) -> go.Figure:
    """Findings grouped by contributing subsystem — Findings section's
    per-finding `source` tag (finding / vulnerability_assessment /
    linux_security_threat_hunting / owasp_web_security /
    owasp_source_code_review)."""
    content = _section_content(report, ReportSectionType.FINDINGS)
    findings = content.get("findings")
    if not isinstance(findings, list) or not findings:
        return _empty_figure("Finding Distribution")
    by_source: dict[str, int] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        source = str(finding.get("source", "unknown"))
        by_source[source] = by_source.get(source, 0) + 1
    labels = sorted(by_source)
    values = [by_source[label] for label in labels]
    figure = go.Figure(data=[go.Bar(x=labels, y=values)])
    figure.update_layout(
        title="Finding Distribution", xaxis_title="Source", yaxis_title="Finding Count"
    )
    return figure


def case_statistics_chart(report: GeneratedReport) -> go.Figure:
    """Every count on `GeneratedReport.statistics` as one comparison bar
    chart — the single "at a glance" case-wide numbers view."""
    stats = report.statistics
    labels_values = [
        ("Findings", stats.finding_count),
        ("Evidence Items", stats.evidence_count),
        ("IOCs", stats.ioc_count),
        ("MITRE Techniques", stats.mitre_technique_count),
        ("Vulnerabilities", stats.vulnerability_count),
        ("Linux Security Findings", stats.linux_security_finding_count),
        ("Linux Advisories", stats.linux_advisory_count),
        ("OWASP Web Findings", stats.owasp_web_finding_count),
        ("OWASP Source Findings", stats.owasp_security_finding_count),
        ("IR Recommendations", stats.incident_response_recommendation_count),
    ]
    labels_values = [(label, value) for label, value in labels_values if value > 0]
    if not labels_values:
        return _empty_figure("Case Statistics")
    labels = [label for label, _ in labels_values]
    values = [value for _, value in labels_values]
    figure = go.Figure(data=[go.Bar(x=labels, y=values)])
    figure.update_layout(title="Case Statistics", yaxis_title="Count")
    figure.update_xaxes(tickangle=-30)
    return figure


#: Name -> builder, in the fixed display order every renderer iterates —
#: the task's eight named chart types, one entry each.
CHART_BUILDERS: dict[str, _ChartBuilder] = {
    "severity_distribution": severity_distribution_chart,
    "risk_trend": risk_trend_chart,
    "timeline": timeline_chart,
    "mitre_heatmap": mitre_heatmap_chart,
    "ioc_categories": ioc_category_chart,
    "threat_intelligence_sources": threat_intelligence_sources_chart,
    "finding_distribution": finding_distribution_chart,
    "case_statistics": case_statistics_chart,
}


def build_all_charts(report: GeneratedReport) -> dict[str, go.Figure]:
    """Every named chart, keyed by `CHART_BUILDERS`'s stable name — the one
    call every renderer uses rather than invoking each builder individually."""
    return {name: builder(report) for name, builder in CHART_BUILDERS.items()}
