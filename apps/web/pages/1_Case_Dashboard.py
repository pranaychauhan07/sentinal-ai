"""Case Dashboard — blueprint §13's "Case Management": list/create/filter
cases by status/severity, each case a first-class object you can revisit.
Mirrors the Claude-Design mockup's Dashboard + Cases screens, folded into
one page per blueprint §6's named file list.
"""

from __future__ import annotations

import streamlit as st

from apps.web.components.cards import render_case_card
from apps.web.components.charts import severity_donut
from apps.web.runtime import run_async
from apps.web.theme import apply_page_config
from core.db.models.case import Case, CasePriority, CaseStatus
from core.exceptions import BusinessRuleError
from core.parsers.models import Severity
from core.services import case_service

apply_page_config("Case Dashboard")

st.title("Case Dashboard")

status_filter = st.sidebar.selectbox(
    "Filter by status", ["all", *[s.value for s in CaseStatus]], index=0
)

cases: list[Case] = run_async(
    lambda session: case_service.list_cases(
        session,
        status=None if status_filter == "all" else CaseStatus(status_filter),
        limit=200,
    )
)

col1, col2, col3 = st.columns([1, 1, 2])
col1.metric("Cases shown", len(cases))
col2.metric(
    "Avg. risk score",
    f"{sum(c.risk_score or 0 for c in cases) / len(cases):.0f}" if cases else "—",
)
with col3:
    st.plotly_chart(severity_donut([c.severity.value for c in cases]), use_container_width=True)

with st.expander("➕ Create a new case"), st.form("create_case_form"):
    title = st.text_input("Title")
    description = st.text_area("Description", "")
    severity = st.selectbox("Severity", [s.value for s in Severity], index=0)
    priority = st.selectbox("Priority", [p.value for p in CasePriority], index=1)
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
                        severity=Severity(severity),
                        priority=CasePriority(priority),
                        analyst_id="local-analyst",
                    )
                )
                st.session_state["case_id"] = str(created.id)
                st.success(f"Case '{created.title}' created.")
                st.rerun()
            except BusinessRuleError as exc:
                st.error(str(exc))

st.subheader("Cases")
if not cases:
    st.info("No cases match this filter yet.")
for case in cases:
    with st.container():
        c1, c2 = st.columns([4, 1])
        with c1:
            render_case_card(case)
        with c2:
            if st.button("Open", key=f"open_case_{case.id}"):
                st.session_state["case_id"] = str(case.id)
                st.success(f"Selected '{case.title}' — use the sidebar to explore it.")
