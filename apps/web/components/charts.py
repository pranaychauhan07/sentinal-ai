"""Plotly chart wrappers — presentation-only (constitution §3): every
builder is a pure function of already-fetched data (counts, rows), never a
re-derivation of a score/severity/confidence the backend already computed
(constitution §1.9). Deliberately independent of `core/reporting/charts.py`
(that package builds figures from an already-*generated* `GeneratedReport`;
these build figures directly from live `core/services` query results for
cross-case/dashboard views a single case's report doesn't cover) — no new
`apps/web -> core/reporting` dependency edge is introduced.
"""

from __future__ import annotations

import datetime as _dt
from collections import Counter

import plotly.graph_objects as go

from apps.web.theme import ACCENT, MUTED, SEVERITY_COLORS, TEXT

#: Deterministic, fixed palette for a small closed set of category labels —
#: any label not in this map falls back to a stable hash-based color so a
#: dashboard with more IOC/event types than named colors never crashes or
#: silently reuses one color for two different categories.
_CATEGORY_PALETTE: tuple[str, ...] = (
    "#7aa2ff",
    "#3ddc97",
    "#f5a524",
    "#ff6b6b",
    "#c792ea",
    "#66d9ef",
    "#ff9f5b",
    "#7dd3fc",
)


def _color_for(label: str, index: int) -> str:
    return _CATEGORY_PALETTE[index % len(_CATEGORY_PALETTE)]


_PLOT_LAYOUT = {
    "paper_bgcolor": "rgba(0,0,0,0)",
    "plot_bgcolor": "rgba(0,0,0,0)",
    "font": {"color": TEXT, "family": "Inter, sans-serif"},
    "margin": {"l": 10, "r": 10, "t": 30, "b": 10},
}


def severity_donut(severities: list[str]) -> go.Figure:
    """A donut of severity counts (case list, finding list, IOC list — any
    `list[str]` of severity values)."""
    counts = Counter(s.lower() for s in severities)
    order = ["critical", "high", "medium", "low", "info"]
    labels = [label for label in order if counts.get(label)]
    values = [counts[label] for label in labels]
    if not labels:
        labels, values = ["no data"], [1]
        colors = [MUTED]
    else:
        colors = [SEVERITY_COLORS.get(label, MUTED) for label in labels]
    fig = go.Figure(
        data=[
            go.Pie(
                labels=[label.upper() for label in labels],
                values=values,
                hole=0.6,
                marker={"colors": colors},
                textfont={"color": TEXT},
            )
        ]
    )
    fig.update_layout(**_PLOT_LAYOUT, showlegend=True, height=280)
    return fig


def mitre_technique_bar(technique_labels: list[str], finding_counts: list[int]) -> go.Figure:
    """A horizontal bar of MITRE techniques hit by a case, ranked by how
    many Findings mapped to each — `pages/5_MITRE_Map.py`'s primary chart."""
    if not technique_labels:
        fig = go.Figure()
        fig.add_annotation(
            text="No MITRE techniques mapped yet for this case",
            showarrow=False,
            font={"color": MUTED},
        )
        fig.update_layout(**_PLOT_LAYOUT, height=200)
        return fig
    fig = go.Figure(
        data=[
            go.Bar(
                x=finding_counts,
                y=technique_labels,
                orientation="h",
                marker={"color": "#7aa2ff"},
            )
        ]
    )
    fig.update_layout(
        **_PLOT_LAYOUT,
        height=max(220, 32 * len(technique_labels)),
        xaxis={"title": "Findings mapped", "gridcolor": "rgba(255,255,255,0.06)"},
        yaxis={"autorange": "reversed"},
    )
    return fig


def timeline_scatter(
    timestamps: list[object], labels: list[str], event_types: list[str]
) -> go.Figure:
    """A one-row scatter timeline of case events — `pages/4_Threat_Timeline.py`'s
    chart, deliberately simple (a chronological strip, not a full Gantt) since
    the underlying data is a flat, ordered `TimelineEvent` list."""
    if not timestamps:
        fig = go.Figure()
        fig.add_annotation(
            text="No timeline events recorded yet", showarrow=False, font={"color": MUTED}
        )
        fig.update_layout(**_PLOT_LAYOUT, height=160)
        return fig
    unique_types = sorted(set(event_types))
    color_map = {
        t: c
        for t, c in zip(
            unique_types,
            ["#7aa2ff", "#3ddc97", "#f5a524", "#ff6b6b", "#c792ea", "#66d9ef"] * 4,
            strict=False,
        )
    }
    fig = go.Figure(
        data=[
            go.Scatter(
                x=timestamps,
                y=[0] * len(timestamps),
                mode="markers",
                marker={
                    "size": 14,
                    "color": [color_map[t] for t in event_types],
                    "line": {"width": 1, "color": "rgba(255,255,255,0.3)"},
                },
                text=labels,
                hoverinfo="text+x",
            )
        ]
    )
    fig.update_layout(
        **_PLOT_LAYOUT,
        height=180,
        yaxis={"visible": False, "range": [-1, 1]},
        xaxis={"gridcolor": "rgba(255,255,255,0.06)"},
    )
    return fig


def category_donut(labels: list[str]) -> go.Figure:
    """A donut of an arbitrary category vocabulary (IOC types, finding
    types, ...) — like `severity_donut`, but for a category that has no
    fixed severity-style color vocabulary. Home dashboard's "Top Threats"
    panel."""
    counts = Counter(labels)
    if not counts:
        ordered_labels, values = ["no data"], [1]
        colors = [MUTED]
    else:
        ordered = counts.most_common()
        ordered_labels = [label for label, _ in ordered]
        values = [count for _, count in ordered]
        colors = [_color_for(label, i) for i, label in enumerate(ordered_labels)]
    fig = go.Figure(
        data=[
            go.Pie(
                labels=[label.upper() for label in ordered_labels],
                values=values,
                hole=0.6,
                marker={"colors": colors},
                textfont={"color": TEXT},
            )
        ]
    )
    fig.update_layout(**_PLOT_LAYOUT, showlegend=True, height=280)
    return fig


def events_per_day_line(dates: list[_dt.date]) -> go.Figure:
    """A daily event-count line — Home dashboard's "Alerts Over Time"
    panel, built from real `TimelineEvent` timestamps across every case,
    never a synthetic/placeholder trend."""
    if not dates:
        fig = go.Figure()
        fig.add_annotation(
            text="No timeline activity recorded yet", showarrow=False, font={"color": MUTED}
        )
        fig.update_layout(**_PLOT_LAYOUT, height=220)
        return fig
    counts = Counter(dates)
    ordered_days = sorted(counts)
    fig = go.Figure(
        data=[
            go.Scatter(
                x=ordered_days,
                y=[counts[day] for day in ordered_days],
                mode="lines+markers",
                line={"color": ACCENT, "width": 2},
                marker={"size": 6, "color": ACCENT},
                fill="tozeroy",
                fillcolor="rgba(122,162,255,0.12)",
            )
        ]
    )
    fig.update_layout(
        **_PLOT_LAYOUT,
        height=220,
        xaxis={"gridcolor": "rgba(255,255,255,0.06)"},
        yaxis={"gridcolor": "rgba(255,255,255,0.06)", "title": "Events"},
    )
    return fig
