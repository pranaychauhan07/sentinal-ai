"""Threat Timeline — blueprint §13: "Chronological reconstruction of events
across all evidence in a case... the single most 'wow' UI element,
directly demonstrat[ing] the cross-evidence correlation architecture is
real, not decorative."
"""

from __future__ import annotations

import streamlit as st

from apps.web.components.case_picker import select_case
from apps.web.components.charts import timeline_scatter
from apps.web.runtime import run_async
from apps.web.theme import apply_page_config
from core.services import case_service

apply_page_config("Threat Timeline")

st.title("Threat Timeline")
case = select_case(key="timeline_case_picker")

if case is not None:
    events = run_async(
        lambda session: case_service.list_timeline_for_case(session, case.id, limit=500)
    )
    events = sorted(events, key=lambda e: e.timestamp)

    if not events:
        st.info("No timeline events recorded for this case yet.")
    else:
        st.plotly_chart(
            timeline_scatter(
                [e.timestamp for e in events],
                [e.narrative for e in events],
                [e.event_type.value for e in events],
            ),
            use_container_width=True,
        )
        st.subheader("Event log")
        for event in events:
            st.markdown(
                f"`{event.timestamp:%Y-%m-%d %H:%M:%S}` — **{event.event_type.value}** — "
                f"{event.narrative}"
            )
