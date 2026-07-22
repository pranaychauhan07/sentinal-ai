"""New Investigation — create a case (or pick an existing one) and upload
evidence, synchronously running the full ingest -> extract -> generate ->
analyze pipeline (`core.services.case_service.investigate_new_evidence`),
per blueprint §9's data flow and M1's demo criterion: "upload a firewall
log, get a real AI-generated severity-classified finding."
"""

from __future__ import annotations

import streamlit as st

from apps.web.components.case_picker import select_case
from apps.web.runtime import get_settings_cached, run_async
from apps.web.theme import apply_page_config
from core.exceptions import AppError, BusinessRuleError
from core.parsers.models import Severity
from core.services import case_service

apply_page_config("New Investigation")

st.title("New Investigation")

tab_existing, tab_new = st.tabs(["Upload to an existing case", "Start a new case"])

with tab_new, st.form("new_case_form"):
    title = st.text_input("Case title")
    description = st.text_area("Description", "")
    submitted = st.form_submit_button("Create case")
    if submitted:
        if not title.strip():
            st.error("Title is required.")
        else:
            try:
                created = run_async(
                    lambda session: case_service.create_case(
                        session,
                        title=title,
                        description=description,
                        severity=Severity.INFO,
                        analyst_id="local-analyst",
                    )
                )
                st.session_state["case_id"] = str(created.id)
                st.success(f"Case '{created.title}' created — now upload evidence below.")
            except BusinessRuleError as exc:
                st.error(str(exc))

st.divider()
st.subheader("Upload evidence")
case = select_case(key="new_investigation_case_picker")

uploaded_files = st.file_uploader(
    "Firewall/IDS/server log, phishing email (.eml/.txt), Nmap/Nessus/OpenVAS scan report, "
    "source code, or an HTTP transaction export",
    accept_multiple_files=True,
)

if case is not None and uploaded_files and st.button("Run investigation pipeline"):
    settings = get_settings_cached()

    for uploaded in uploaded_files:
        content = uploaded.getvalue()
        with st.spinner(f"Running Coordinator + specialist agents on {uploaded.name}..."):

            def _run(session, uploaded=uploaded, content=content):
                return case_service.investigate_new_evidence(
                    session,
                    case_id=case.id,
                    filename=uploaded.name,
                    content=content,
                    settings=settings,
                    ingested_by="local-analyst",
                )

            try:
                result = run_async(_run)
            except AppError as exc:
                st.error(f"**{uploaded.name}** couldn't be processed: {exc}")
                st.divider()
                continue

        st.success(f"Investigation complete for **{uploaded.name}**.")
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("IOCs extracted", result.ioc_count)
        c2.metric("Findings created", len(result.created_finding_ids))
        c3.metric("Findings merged", len(result.merged_finding_ids))
        c4.metric("MITRE techniques", result.mitre_technique_count or 0)

        if result.soc_risk_label:
            st.markdown(f"**SOC risk:** {result.soc_risk_label} ({result.soc_risk_score:.0f})")
        if result.phishing_risk_label:
            st.markdown(
                f"**Phishing risk:** {result.phishing_risk_label} "
                f"({result.phishing_risk_score:.0f})"
            )
        if result.vulnerability_finding_count:
            st.markdown(
                f"**Vulnerability findings:** {result.vulnerability_finding_count} "
                f"(highest CVSS {result.highest_vulnerability_score})"
            )
        if result.linux_security_finding_count:
            st.markdown(f"**Threat hunting findings:** {result.linux_security_finding_count}")
        if result.incident_severity:
            st.markdown(f"**Incident severity:** {result.incident_severity}")
        if result.report_id:
            st.markdown(
                f"**Report generated:** {result.report_type} "
                f"({result.report_section_count} sections, "
                f"confidence {result.report_confidence:.0%}) — see **Executive Reports**."
            )
        st.divider()

    st.info("See **Evidence Explorer**, **Threat Timeline**, and **MITRE ATT&CK** for full detail.")
