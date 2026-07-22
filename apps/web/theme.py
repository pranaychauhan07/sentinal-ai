"""Shared dark-theme styling + page configuration — every page calls
`apply_page_config()` first thing, mirroring blueprint §13's "dark-theme-
first (SOC tools are dark-themed for a reason: analysts stare at these for
hours)".

Palette, typography (Inter/IBM Plex Mono), card treatment, severity-pill
colors, and sidebar nav states are ported directly from the Claude-Design
mockup handed off for this build (`AI Cyber Defense Copilot-handoff/
ai-cyber-defense-copilot/project/{AppShell,Dashboard}.dc.html`) — the exact
`rgba(255,255,255,0.03)` card fill, `12px` card radius, and per-severity
text/background pairs are copied from those files, not approximated. What's
still a recreation rather than a pixel-for-pixel port is the mockup's custom
flexbox shell itself (a fixed-width sidebar + blurred topbar the mockup
hand-builds in HTML/CSS) — Streamlit's own sidebar/main-content model is
restyled to match its *look*, not rebuilt as a competing layout engine (see
the conversation history for why React was considered and Streamlit was
chosen instead for this phase). Presentation only — no business logic, per
docs/dependency-rules.md rule 3.
"""

from __future__ import annotations

import streamlit as st

BG = "#0a0b0e"
SIDEBAR_BG = "#0c0d12"
TEXT = "#e8eaf0"
MUTED = "#9aa1b0"
DIM = "#6b7280"
ACCENT = "#7aa2ff"
ACCENT_DEEP = "#4d6fd6"
BORDER = "rgba(255,255,255,0.07)"
SUCCESS = "#3ddc97"
DANGER = "#ff6b6b"
WARNING = "#ff9f5b"

#: `(text, background)` pairs — copied verbatim from `Dashboard.dc.html`'s
#: `SEV_COLOR` map, the mockup's own severity palette.
SEVERITY_PALETTE: dict[str, tuple[str, str]] = {
    "critical": (DANGER, "rgba(255,107,107,0.14)"),
    "high": (WARNING, "rgba(255,159,91,0.14)"),
    "medium": ("#f5c451", "rgba(245,196,81,0.14)"),
    "low": ("#7dd3fc", "rgba(125,211,252,0.14)"),
    "info": (MUTED, "rgba(154,161,176,0.12)"),
}
#: Back-compat flat map (a single color per severity) for callers that only
#: need one color, e.g. Plotly marker fills (`components/charts.py`).
SEVERITY_COLORS: dict[str, str] = {k: v[0] for k, v in SEVERITY_PALETTE.items()}

_FONTS = (
    "<link rel='preconnect' href='https://fonts.googleapis.com'>"
    "<link rel='preconnect' href='https://fonts.gstatic.com' crossorigin>"
    "<link href='https://fonts.googleapis.com/css2?"
    "family=Inter:wght@400;500;600;700&family=IBM+Plex+Mono:wght@500;600;700"
    "&display=swap' rel='stylesheet'>"
)

_CSS = f"""<style>
html, body, .stApp {{
    background-color: {BG}; color: {TEXT};
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
}}
code, pre, .sentinel-mono {{ font-family: 'IBM Plex Mono', monospace; }}
/* ---- Sidebar shell ---- */
section[data-testid="stSidebar"] {{
    background-color: {SIDEBAR_BG}; border-right: 1px solid {BORDER};
}}
section[data-testid="stSidebar"] [data-testid="stSidebarNav"] a {{
    border-radius: 8px; color: {MUTED}; font-size: 13px; font-weight: 500;
    transition: background .15s ease, color .15s ease;
}}
section[data-testid="stSidebar"] [data-testid="stSidebarNav"] a:hover {{
    background: rgba(255,255,255,0.04); color: {TEXT};
}}
section[data-testid="stSidebar"] [data-testid="stSidebarNav"] a[aria-current="page"] {{
    background: rgba(122,162,255,0.12); color: #dbe4ff; font-weight: 600;
}}
/* ---- Cards / metrics ---- */
div[data-testid="stMetric"], div[data-testid="stExpander"], .sentinel-card {{
    background: rgba(255,255,255,0.03); border: 1px solid {BORDER};
    border-radius: 12px; padding: 16px 18px;
}}
div[data-testid="stMetricValue"] {{
    font-family: 'IBM Plex Mono', monospace; font-weight: 700;
}}
.sentinel-card {{ margin-bottom: 10px; padding: 14px 16px; }}
.sentinel-muted {{ color: {MUTED}; font-size: 12.5px; }}
.sentinel-mono-muted {{
    color: {DIM}; font-size: 11.5px; font-family: 'IBM Plex Mono', monospace;
}}
/* ---- Severity / status pills (mockup: rounded, text+bg pair, 11px/600) ---- */
.sentinel-badge {{
    display:inline-block; padding:3px 9px; border-radius:20px;
    font-size:11px; font-weight:600; letter-spacing: 0.2px;
}}
/* ---- Inputs / buttons ---- */
.stTextInput input, .stTextArea textarea, .stSelectbox [data-baseweb="select"] > div {{
    background: rgba(255,255,255,0.04) !important;
    border: 1px solid rgba(255,255,255,0.07) !important;
    border-radius: 8px !important; color: {TEXT} !important;
}}
.stButton button, .stFormSubmitButton button {{
    border-radius: 8px; border: 1px solid rgba(122,162,255,0.35);
    background: linear-gradient(135deg, {ACCENT}, {ACCENT_DEEP});
    color: #0a0b0e; font-weight: 600;
}}
.stButton button:hover, .stFormSubmitButton button:hover {{
    border-color: {ACCENT}; filter: brightness(1.08);
}}
/* ---- Status pill (sidebar "N agents nominal" indicator) ---- */
.sentinel-status-pill {{
    display:flex; align-items:center; gap:8px; padding:10px 8px;
    border-radius:8px; background: rgba(255,255,255,0.03);
    border: 1px solid rgba(255,255,255,0.06); margin-top: 10px;
}}
.sentinel-status-dot {{
    width:8px; height:8px; border-radius:50%; background:{SUCCESS};
    flex-shrink: 0;
}}
.sentinel-brand {{
    display:flex; align-items:center; gap:9px; padding:2px 2px 14px 2px;
}}
.sentinel-brand-mark {{
    width:22px; height:22px; border-radius:6px; flex-shrink:0;
    background: linear-gradient(135deg, {ACCENT}, {ACCENT_DEEP});
}}
.sentinel-brand-name {{ font-size:14px; font-weight:700; letter-spacing:-0.2px; }}
</style>"""


def severity_pill_html(label: str) -> str:
    """A severity pill matching the mockup's `sevPillStyle` exactly
    (colored text on a tinted background, not a solid fill)."""
    text_color, bg_color = SEVERITY_PALETTE.get(label.lower(), SEVERITY_PALETTE["info"])
    return (
        f'<span class="sentinel-badge" style="color:{text_color};background:{bg_color}">'
        f"{label.upper()}</span>"
    )


def apply_page_config(title: str) -> None:
    """Sets the page tab title/layout, injects the shared dark CSS/fonts,
    and renders the sidebar brand header + system-status pill (the
    mockup's `AppShell.dc.html` sidebar top/bottom) — called once, first
    line, in every `Home.py`/`pages/*.py` file."""
    st.set_page_config(
        page_title=f"Sentinel Copilot — {title}", layout="wide", initial_sidebar_state="expanded"
    )
    st.markdown(_FONTS + _CSS, unsafe_allow_html=True)
    with st.sidebar:
        st.markdown(
            '<div class="sentinel-brand">'
            '<div class="sentinel-brand-mark"></div>'
            '<div class="sentinel-brand-name">Sentinel Copilot</div>'
            "</div>",
            unsafe_allow_html=True,
        )
