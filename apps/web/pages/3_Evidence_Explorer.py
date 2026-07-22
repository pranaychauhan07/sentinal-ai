"""Evidence Explorer — blueprint §13: "Raw + parsed view of every uploaded
artifact... so an analyst can verify the parser didn't miss something,"
folding in the Findings and IOC Explorer views (the Claude-Design mockup's
separate IocExplorer screen) as tabs of the same case-scoped page.
"""

from __future__ import annotations

import streamlit as st

from apps.web.components.badges import render_severity_badge, render_status_badge
from apps.web.components.case_picker import select_case
from apps.web.runtime import run_async
from apps.web.theme import apply_page_config
from core.services.evidence_service import list_evidence_for_case
from core.services.finding_service import list_findings_for_case
from core.services.threat_intel_service import list_iocs_for_case

apply_page_config("Evidence Explorer")

st.title("Evidence Explorer")
case = select_case(key="evidence_explorer_case_picker")

if case is not None:
    tab_evidence, tab_findings, tab_iocs = st.tabs(["Evidence", "Findings", "IOCs"])

    with tab_evidence:
        evidence_rows = run_async(
            lambda session: list_evidence_for_case(session, case.id, limit=200)
        )
        if not evidence_rows:
            st.info("No evidence uploaded to this case yet.")
        for row in evidence_rows:
            with st.expander(f"{row.original_filename} — {row.evidence_type.value}"):
                c1, c2, c3 = st.columns(3)
                c1.metric("Status", row.status.value)
                c2.metric("Parser", row.parser_name or "—")
                c3.metric(
                    "Parser confidence",
                    f"{row.parser_confidence:.0%}" if row.parser_confidence is not None else "—",
                )
                st.caption(f"SHA-256: `{row.sha256}` · {row.file_size_bytes:,} bytes")

    with tab_findings:
        finding_rows = run_async(
            lambda session: list_findings_for_case(session, case.id, limit=200)
        )
        if not finding_rows:
            st.info("No findings generated for this case yet.")
        for finding in finding_rows:
            with st.container():
                c1, c2 = st.columns([4, 1])
                with c1:
                    st.markdown(f"**{finding.title}**")
                    st.caption(finding.description)
                with c2:
                    render_severity_badge(finding.severity.value)
                    render_status_badge(finding.status.value)
                st.caption(
                    f"Risk score: {finding.risk_score:.0f} · Confidence: "
                    f"{finding.confidence:.0%} · Priority: {finding.priority.value} · "
                    f"{finding.ioc_count} supporting IOC(s)"
                )
                st.divider()

    with tab_iocs:
        ioc_rows = run_async(lambda session: list_iocs_for_case(session, case.id, limit=500))
        if not ioc_rows:
            st.info("No IOCs extracted for this case yet.")
        else:
            st.dataframe(
                [
                    {
                        "Type": ioc.ioc_type.value,
                        "Value": ioc.value,
                        "Severity": ioc.severity.value,
                        "Classification": ioc.classification.value,
                        "Confidence": f"{ioc.confidence:.0%}",
                        "Composite score": round(ioc.composite_score, 1),
                        "Status": ioc.status.value,
                    }
                    for ioc in ioc_rows
                ],
                use_container_width=True,
                hide_index=True,
            )
