"""Severity/status/confidence badge rendering — presentation-only helpers
shared across pages (`apps/web/components/README.md`). Every function here
accepts already-computed data (a severity enum value, a confidence float)
and returns markup to render; none of them look anything up or make a
decision (constitution §3).

Pill styling (colored text on a tinted background, not a solid fill) mirrors
`Dashboard.dc.html`'s `SEV_COLOR`/pill treatment from the handoff mockup.
"""

from __future__ import annotations

import streamlit as st

from apps.web.theme import ACCENT, DIM, MUTED, SEVERITY_PALETTE, SUCCESS, WARNING

#: `(text, background)` pairs for case/finding/evidence status values —
#: same visual language as `theme.SEVERITY_PALETTE`, just a different
#: vocabulary (lifecycle state rather than severity).
_STATUS_PALETTE: dict[str, tuple[str, str]] = {
    "open": (ACCENT, "rgba(122,162,255,0.14)"),
    "investigating": (WARNING, "rgba(255,159,91,0.14)"),
    "closed": (MUTED, "rgba(154,161,176,0.12)"),
    "resolved": (SUCCESS, "rgba(61,220,151,0.14)"),
    "escalated": ("#ff6b6b", "rgba(255,107,107,0.14)"),
    "on_hold": (DIM, "rgba(107,114,128,0.14)"),
    "contained": (SUCCESS, "rgba(61,220,151,0.14)"),
    "archived": (DIM, "rgba(107,114,128,0.14)"),
    "merged": (DIM, "rgba(107,114,128,0.14)"),
}


def severity_badge(severity: str) -> str:
    text_color, bg_color = SEVERITY_PALETTE.get(severity.lower(), SEVERITY_PALETTE["info"])
    return (
        f'<span class="sentinel-badge" style="color:{text_color};background:{bg_color}">'
        f"{severity.upper()}</span>"
    )


def render_severity_badge(severity: str) -> None:
    st.markdown(severity_badge(severity), unsafe_allow_html=True)


def status_badge(status: str) -> str:
    text_color, bg_color = _STATUS_PALETTE.get(status.lower(), (MUTED, "rgba(154,161,176,0.12)"))
    label = status.replace("_", " ").upper()
    return (
        f'<span class="sentinel-badge" style="color:{text_color};background:{bg_color}">'
        f"{label}</span>"
    )


def render_status_badge(status: str) -> None:
    st.markdown(status_badge(status), unsafe_allow_html=True)


def confidence_label(confidence: float) -> str:
    """Mirrors `core.tools.memory_tools`'s confidence-bucketing thresholds
    (high >= 0.7, medium >= 0.4, else low) for a consistent vocabulary
    across the whole app — display-only, never a scoring decision."""
    if confidence >= 0.7:
        return "high"
    if confidence >= 0.4:
        return "medium"
    return "low"
