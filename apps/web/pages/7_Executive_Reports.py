"""Executive Reports — blueprint §13: "One-click PDF per module or full-case
executive summary, previewable in-app before download," backed by the
Report Export Framework (ADR-0026).
"""

from __future__ import annotations

import streamlit as st
import streamlit.components.v1 as components

from apps.web.components.case_picker import select_case
from apps.web.runtime import run_async
from apps.web.theme import apply_page_config
from core.exceptions import NotFoundError
from core.services.report_export_service import (
    export_report,
    list_supported_formats,
    preview_report,
)

apply_page_config("Executive Reports")

st.title("Executive Reports")
case = select_case(key="reports_case_picker")

if case is not None:
    theme_choice = st.radio("Theme", ["dark", "light"], horizontal=True, index=0)

    try:
        preview = run_async(
            lambda session: preview_report(session, case_id=case.id, theme=theme_choice)
        )
    except NotFoundError:
        st.info(
            "No report has been generated for this case yet — upload evidence on "
            "**New Investigation** first; a Technical Investigation Report is generated "
            "automatically on every upload."
        )
    else:
        st.subheader("Preview")
        components.html(preview.content.decode("utf-8"), height=800, scrolling=True)

        st.subheader("Download")
        cols = st.columns(len(list_supported_formats()))
        for col, fmt in zip(cols, list_supported_formats(), strict=False):
            with col:
                if st.button(f"Export {fmt.value.upper()}", key=f"export_{fmt.value}"):
                    exported = run_async(
                        lambda session, fmt=fmt: export_report(
                            session,
                            case_id=case.id,
                            export_format=fmt,
                            theme=theme_choice,
                            include_charts=True,
                        )
                    )
                    st.download_button(
                        f"Download {exported.filename}",
                        data=exported.content,
                        file_name=exported.filename,
                        mime=exported.media_type,
                        key=f"download_{fmt.value}",
                    )
