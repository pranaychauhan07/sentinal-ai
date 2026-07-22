"""Shared case-selection widget — every case-scoped page (Evidence Explorer,
Threat Timeline, MITRE Map, AI Analyst Chat, Reports) needs the analyst to
pick which case they're looking at. Streamlit has no native cross-page
routing state, so the chosen id lives in `st.session_state["case_id"]`
(set here, read by every subsequent page) — presentation-only, no business
logic (constitution §3).
"""

from __future__ import annotations

import uuid

import streamlit as st

from apps.web.runtime import run_async
from core.db.models.case import Case
from core.exceptions import BusinessRuleError
from core.services import case_service


def select_case(*, key: str = "case_picker") -> Case | None:
    """Renders a case picker (defaulting to whichever case was last selected
    on any page, via `st.session_state["case_id"]`) and returns the chosen
    `Case`, or `None` if no case exists yet.

    An empty case list previously rendered a bare info message and hid every
    other control on the page (including e.g. the AI Chat's `st.chat_input`)
    — from a first run with an empty database, every case-scoped page looked
    identical and non-interactive. This now offers an inline "create a case"
    form right here, so any case-scoped page is a valid starting point, not
    just Case Dashboard/New Investigation.
    """
    cases = run_async(lambda session: case_service.list_cases(session, limit=200))
    if not cases:
        st.info("No cases yet. Create one below to get started, or use the links underneath.")
        with st.form(f"{key}__quick_create"):
            title = st.text_input("Case title", key=f"{key}__quick_create_title")
            created_clicked = st.form_submit_button("Create case")
        if created_clicked:
            if not title.strip():
                st.error("Title is required.")
            else:
                try:
                    created = run_async(
                        lambda session: case_service.create_case(
                            session,
                            title=title,
                            analyst_id="local-analyst",
                        )
                    )
                except BusinessRuleError as exc:
                    st.error(str(exc))
                else:
                    st.session_state["case_id"] = str(created.id)
                    st.success(f"Case '{created.title}' created.")
                    st.rerun()
        cols = st.columns(2)
        with cols[0]:
            st.page_link("pages/1_Case_Dashboard.py", label="Open Case Dashboard", icon="📋")
        with cols[1]:
            st.page_link(
                "pages/2_New_Investigation.py", label="Start a New Investigation", icon="🔎"
            )
        return None

    options = {str(case.id): case for case in cases}
    labels = {
        case_id: f"{case.title}  ({case.status.value}, {case.severity.value})"
        for case_id, case in options.items()
    }

    current = st.session_state.get("case_id")
    ids = list(options.keys())
    default_index = ids.index(current) if current in ids else 0

    selected_id = st.selectbox(
        "Case", ids, index=default_index, format_func=lambda i: labels[i], key=key
    )
    st.session_state["case_id"] = selected_id
    return options[selected_id]


def get_selected_case_id() -> uuid.UUID | None:
    raw = st.session_state.get("case_id")
    return uuid.UUID(raw) if raw else None
