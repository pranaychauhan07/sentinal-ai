"""Sentinel Copilot — entry point. The Security Operations Dashboard:
blueprint §13's "walk up and understand system health in 5 seconds" screen,
laid out to match the handoff mockup's `Dashboard.dc.html` (stat cards,
alerts-over-time trend, threat/MITRE breakdowns, recent activity feed, AI
insights bar) — built entirely from real, already-persisted case data via
`core/services` (no synthetic/placeholder deltas: this dashboard has no
historical baseline to compare against yet, so it never fabricates a
"+12% vs last 24h"-style change figure the backend hasn't computed).
"""

from __future__ import annotations

import datetime as dt
from collections import Counter

import streamlit as st

from apps.web.components.cards import render_case_card
from apps.web.components.charts import category_donut, events_per_day_line, mitre_technique_bar
from apps.web.runtime import run_async
from apps.web.theme import SEVERITY_PALETTE, apply_page_config
from core.db.models.case import CaseStatus
from core.services import case_service, finding_service, threat_intel_service

apply_page_config("Home")

_OPEN_STATUSES = {CaseStatus.OPEN, CaseStatus.INVESTIGATING, CaseStatus.ESCALATED}
_RESOLVED_STATUSES = {CaseStatus.RESOLVED, CaseStatus.CLOSED, CaseStatus.CONTAINED}

#: Event-type -> dot color, mirroring the mockup's `recentActivity` dot
#: styling (category -> color) — a fixed, deterministic map over the real,
#: closed `TimelineEventType` enum, not a fabricated classification.
_EVENT_DOT_COLOR = {
    "case_opened": "#7aa2ff",
    "evidence_ingested": "#7aa2ff",
    "ioc_extracted": "#f5c451",
    "finding_generated": "#ff6b6b",
    "agent_analysis": "#a78bfa",
    "case_status_changed": "#9aa1b0",
    "manual_note": "#9aa1b0",
    "case_assigned": "#9aa1b0",
    "vulnerability_assessed": "#ff9f5b",
    "linux_security_finding_detected": "#ff6b6b",
    "linux_advisory_assessed": "#a78bfa",
    "owasp_web_assessed": "#ff9f5b",
    "sast_assessed": "#ff9f5b",
    "incident_response_plan_generated": "#3ddc97",
    "report_generated": "#3ddc97",
}


def _time_ago(timestamp: dt.datetime) -> str:
    now = (
        dt.datetime.now(timestamp.tzinfo)
        if timestamp.tzinfo
        else dt.datetime.now(dt.UTC).replace(tzinfo=None)
    )
    delta = now - timestamp
    seconds = max(0, int(delta.total_seconds()))
    if seconds < 60:
        return "just now"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m ago"
    hours = minutes // 60
    if hours < 24:
        return f"{hours}h ago"
    days = hours // 24
    return f"{days}d ago"


async def _load_dashboard_data(session):
    cases = await case_service.list_cases(session, limit=200)
    findings = []
    iocs = []
    tactic_counts: Counter[str] = Counter()
    technique_count = 0
    events = []
    for case in cases:
        findings.extend(await finding_service.list_findings_for_case(session, case.id, limit=500))
        iocs.extend(await threat_intel_service.list_iocs_for_case(session, case.id, limit=500))
        mappings = await finding_service.list_mitre_mappings_for_case(session, case.id)
        technique_count += len(mappings)
        for mapping in mappings:
            for tactic in mapping.tactic_shortnames:
                tactic_counts[tactic] += mapping.finding_count
        events.extend(await case_service.list_timeline_for_case(session, case.id, limit=200))
    return cases, findings, iocs, tactic_counts, technique_count, events


st.title("🛡️ Security Operations Dashboard")
st.caption("AI-native, case-centric SOC analyst workbench")

cases, findings, iocs, tactic_counts, technique_count, events = run_async(_load_dashboard_data)

open_cases = [c for c in cases if c.status in _OPEN_STATUSES]
resolved_cases = [c for c in cases if c.status in _RESOLVED_STATUSES]
high_severity_findings = [f for f in findings if f.severity.value in {"critical", "high"}]
critical_findings = [f for f in findings if f.severity.value == "critical"]

# ---- Stat card row ----
c1, c2, c3, c4 = st.columns(4)
c1.metric("Total Alerts", len(iocs), help="Total IOCs extracted across every case")
c2.metric("High Severity", len(high_severity_findings), help="Findings rated Critical or High")
c3.metric("Incidents", len(open_cases), help="Cases currently Open/Investigating/Escalated")
c4.metric("Resolved", len(resolved_cases), help="Cases Resolved/Closed/Contained")

st.divider()

# ---- Trend + breakdowns ----
left, right = st.columns([2, 1])
with left:
    st.subheader("Alerts Over Time")
    event_dates = [e.timestamp.date() for e in events]
    st.plotly_chart(events_per_day_line(event_dates), use_container_width=True)

    st.subheader("Active Cases")
    if not cases:
        st.info("No cases yet — create your first investigation to get started.")
        link_cols = st.columns(2)
        with link_cols[0]:
            st.page_link("pages/1_Case_Dashboard.py", label="Open Case Dashboard", icon="📋")
        with link_cols[1]:
            st.page_link(
                "pages/2_New_Investigation.py", label="Start a New Investigation", icon="🔎"
            )
    else:
        for case in cases[:6]:
            render_case_card(case)

with right:
    st.subheader("Top IOC Types")
    st.plotly_chart(category_donut([ioc.ioc_type.value for ioc in iocs]), use_container_width=True)

    st.subheader("MITRE ATT&CK Tactics")
    top_tactics = tactic_counts.most_common(7)
    st.plotly_chart(
        mitre_technique_bar([t for t, _ in top_tactics], [n for _, n in top_tactics]),
        use_container_width=True,
    )

st.divider()

# ---- Recent activity ----
st.subheader("Recent Activity")
recent_events = sorted(events, key=lambda e: e.timestamp, reverse=True)[:8]
if not recent_events:
    st.caption("No timeline activity recorded yet.")
else:
    for event in recent_events:
        dot_color = _EVENT_DOT_COLOR.get(event.event_type.value, "#9aa1b0")
        st.markdown(
            f'<div style="display:flex;gap:10px;align-items:flex-start;padding:6px 2px">'
            f'<div style="width:7px;height:7px;border-radius:50%;margin-top:6px;'
            f'flex-shrink:0;background:{dot_color}"></div>'
            f'<div style="flex:1"><span style="font-size:13px">{event.narrative}</span>'
            f'<div class="sentinel-mono-muted">{_time_ago(event.timestamp)}</div></div>'
            f"</div>",
            unsafe_allow_html=True,
        )

st.divider()

# ---- AI insights bar ----
triage_count = len([c for c in cases if c.status == CaseStatus.OPEN])
insight_parts = []
if critical_findings:
    insight_parts.append(f"Investigate {len(critical_findings)} critical finding(s)")
if technique_count:
    insight_parts.append(f"Review {technique_count} MITRE technique mapping(s)")
if triage_count:
    insight_parts.append(f"Triage {triage_count} new case(s)")
insight_text = " · ".join(insight_parts) if insight_parts else "No outstanding action items"
critical_color = SEVERITY_PALETTE["critical"][0]
st.markdown(
    f'<div class="sentinel-card" style="display:flex;align-items:center;gap:10px">'
    f'<span style="color:{critical_color};font-weight:700">AI Insights</span>'
    f'<span class="sentinel-muted">{insight_text}</span>'
    f"</div>",
    unsafe_allow_html=True,
)

st.markdown(
    "Use the sidebar to open **Case Dashboard**, start a **New Investigation**, "
    "explore evidence/IOCs, view the **MITRE ATT&CK** coverage map, chat with the "
    "**AI Analyst**, or generate an **Executive Report**."
)
