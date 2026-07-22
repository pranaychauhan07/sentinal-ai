"""MITRE ATT&CK Coverage — blueprint §13's "ATT&CK matrix heatmap
highlighting which tactics/techniques this case touched," backed by the new
`core.services.finding_service.list_mitre_mappings_for_case` (added this
session — every other read-only case view already had a corresponding
`core/services` list function; this was the one genuine gap).
"""

from __future__ import annotations

import streamlit as st

from apps.web.components.case_picker import select_case
from apps.web.components.charts import mitre_technique_bar
from apps.web.runtime import run_async
from apps.web.theme import apply_page_config
from core.services.finding_service import list_mitre_mappings_for_case

apply_page_config("MITRE ATT&CK Coverage")

st.title("MITRE ATT&CK Coverage")
case = select_case(key="mitre_case_picker")

if case is not None:
    summaries = run_async(lambda session: list_mitre_mappings_for_case(session, case.id))

    if not summaries:
        st.info("No MITRE techniques mapped for this case yet.")
    else:
        labels = [f"{s.technique_id} — {s.technique_name}" for s in summaries]
        st.plotly_chart(
            mitre_technique_bar(labels, [s.finding_count for s in summaries]),
            use_container_width=True,
        )

        st.subheader("Techniques")
        for summary in summaries:
            tactics = ", ".join(summary.tactic_shortnames) or "—"
            st.markdown(
                f"**{summary.technique_id} — {summary.technique_name}** "
                f"({summary.finding_count} finding(s), max confidence "
                f"{summary.max_confidence:.0%})"
            )
            st.caption(f"Tactics: {tactics}")
