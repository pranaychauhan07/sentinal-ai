"""Case summary card rendering — presentation-only (constitution §3): every
function accepts an already-fetched `core.db.models.case.Case` row and
renders it, never queries or mutates anything itself.
"""

from __future__ import annotations

import streamlit as st

from apps.web.components.badges import severity_badge, status_badge
from core.db.models.case import Case


def render_case_card(case: Case) -> None:
    risk = f"{case.risk_score:.0f}" if case.risk_score is not None else "—"
    badges = f"{status_badge(case.status.value)}{severity_badge(case.severity.value)}"
    st.markdown(
        f"""
        <div class="sentinel-card">
          <div style="display:flex;justify-content:space-between;align-items:center;gap:10px">
            <div style="font-weight:600;font-size:14px">{case.title}</div>
            <div style="display:flex;gap:6px">{badges}</div>
          </div>
          <div class="sentinel-muted" style="margin-top:6px">
            Priority: {case.priority.value.upper()} &nbsp;·&nbsp;
            Risk score: {risk} &nbsp;·&nbsp; Analyst: {case.analyst_id}
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
