"""HTML Renderer — the task's named "HTML Renderer".

Renders a `GeneratedReport` to a single, self-contained, responsive HTML
document (`templates/report.html.j2`): dark/light mode (via `ReportTheme`),
a print stylesheet, embedded interactive Plotly charts, collapsible
sections (native `<details>`/`<summary>`, no JavaScript required for that
part), and an anchor-link navigation sidebar.

"Self-contained" is a deliberate design choice, not an accident: Plotly's
JS runtime (`plotly.offline.get_plotlyjs()`) is embedded inline once per
document rather than referenced from a CDN, so the exported HTML file opens
correctly with no network access — the same offline-capable goal blueprint
§5 states for the rest of this application. This does make the file larger
(~5 MB baseline for the embedded Plotly runtime); `include_charts=False`
skips chart embedding entirely (and the JS payload with it) for a caller
that wants a lighter-weight document.
"""

from __future__ import annotations

from core.reporting.chart_image_encoder import DEFAULT_CHART_HEIGHT, DEFAULT_CHART_WIDTH
from core.reporting.charts import build_all_charts
from core.reporting.models import GeneratedReport
from core.reporting.template_engine import ReportTemplateEngine
from core.reporting.theme import ReportTheme, resolve_theme


class HTMLReportRenderer:
    """Logo/branding embedding is the caller's job (`asset_manager.
    AssetManager.to_data_uri` -> `ReportTheme.logo_data_uri`) before a theme
    reaches this renderer — this class only ever consumes an
    already-resolved `ReportTheme`, it never talks to `AssetManager`
    itself."""

    def __init__(self, *, template_engine: ReportTemplateEngine | None = None) -> None:
        self._template_engine = template_engine or ReportTemplateEngine()

    def render(
        self,
        report: GeneratedReport,
        *,
        theme: ReportTheme | str | None = None,
        include_charts: bool = True,
    ) -> str:
        resolved_theme = resolve_theme(theme)
        charts_html: dict[str, str] = {}
        plotlyjs: str | None = None
        if include_charts:
            from plotly.offline import get_plotlyjs

            for name, figure in build_all_charts(report).items():
                figure.update_layout(width=DEFAULT_CHART_WIDTH, height=DEFAULT_CHART_HEIGHT)
                charts_html[name] = figure.to_html(include_plotlyjs=False, full_html=False)
            if charts_html:
                plotlyjs = get_plotlyjs()

        return self._template_engine.render(
            "report.html.j2",
            report=report,
            theme=resolved_theme,
            charts_html=charts_html,
            plotlyjs=plotlyjs,
        )

    def render_bytes(
        self,
        report: GeneratedReport,
        *,
        theme: ReportTheme | str | None = None,
        include_charts: bool = True,
    ) -> bytes:
        return self.render(report, theme=theme, include_charts=include_charts).encode("utf-8")
