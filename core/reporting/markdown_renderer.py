"""Markdown Renderer — the task's named "Markdown Renderer"
(`ReportFormat.MARKDOWN`).

Hand-built via plain string joining rather than routed through
`template_engine.py`: Markdown has no equivalent of HTML's script-execution
risk, so the injection concern `template_engine.py` exists to structurally
prevent doesn't apply here in the same way — the one thing this renderer
does guard is Markdown *syntax* corruption (a case value containing `|`
inside a table cell, or a leading `#`/`*` that would be misread as
structural Markdown) via `_escape_markdown`, so attacker- or
analyst-authored case text can never break a report's layout or (in a
Markdown viewer that renders embedded HTML) inject markup.

Chart embedding: a chart is included as a Markdown image referencing a
base64 `data:` URI (`asset_manager.AssetManager.to_data_uri`) — the same
self-contained, offline-viewable property `html_renderer.py` has, since
plain Markdown has no equivalent of an inline `<script>` runtime to embed
an interactive chart into.
"""

from __future__ import annotations

from core.reporting.asset_manager import AssetManager
from core.reporting.chart_image_encoder import (
    ChartImageEncoder,
    KaleidoChartImageEncoder,
    safe_encode,
)
from core.reporting.charts import build_all_charts
from core.reporting.models import GeneratedReport, ReportSection

_MARKDOWN_SPECIAL_CHARS = ("|", "*", "_", "#", "`", "[", "]")


def _escape_markdown(value: object) -> str:
    text = str(value)
    for char in _MARKDOWN_SPECIAL_CHARS:
        text = text.replace(char, f"\\{char}")
    return text


def _render_value(value: object, *, depth: int = 0) -> str:
    if isinstance(value, dict):
        lines = []
        for key, item in value.items():
            rendered = _render_value(item, depth=depth + 1)
            if "\n" in rendered:
                lines.append(f"{'  ' * depth}- **{_escape_markdown(key)}**:\n{rendered}")
            else:
                lines.append(f"{'  ' * depth}- **{_escape_markdown(key)}**: {rendered}")
        return "\n".join(lines)
    if isinstance(value, list | tuple):
        if not value:
            return "_(none)_"
        if all(isinstance(item, dict) for item in value):
            return _render_table(list(value))
        return "\n".join(
            f"{'  ' * depth}- {_render_value(item, depth=depth + 1)}" for item in value
        )
    return _escape_markdown(value)


def _render_table(rows: list[dict[str, object]]) -> str:
    if not rows:
        return "_(none)_"
    headers = list(rows[0].keys())
    lines = [
        "| " + " | ".join(_escape_markdown(h) for h in headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(_escape_markdown(row.get(h, "")) for h in headers) + " |")
    return "\n".join(lines)


def _render_section(section: ReportSection) -> str:
    heading = f"## {_escape_markdown(section.title)}\n"
    if section.is_empty:
        return heading + "\n_No data available for this section._\n"
    return heading + "\n" + _render_value(section.content) + "\n"


class MarkdownReportRenderer:
    def __init__(
        self,
        *,
        asset_manager: AssetManager | None = None,
        chart_image_encoder: ChartImageEncoder | None = None,
    ) -> None:
        self._asset_manager = asset_manager or AssetManager()
        self._chart_image_encoder = chart_image_encoder or KaleidoChartImageEncoder()

    def render(self, report: GeneratedReport, *, include_charts: bool = True) -> str:
        lines = [
            f"# {_escape_markdown(report.title)}",
            "",
            f"**Case:** {_escape_markdown(report.case_id)}  ",
            f"**Type:** {_escape_markdown(report.report_type.value)}  ",
            f"**Generated:** {_escape_markdown(report.generated_at.isoformat())}  ",
            f"**Confidence:** {report.confidence * 100:.0f}%  ",
            f"**Status:** {'Degraded' if report.degraded else 'Complete'}",
            "",
        ]
        if report.degraded and report.degraded_reasons:
            lines.append("> " + "; ".join(_escape_markdown(r) for r in report.degraded_reasons))
            lines.append("")

        lines.append("## Table of Contents")
        for section in report.sections:
            anchor = section.section_type.value.replace("_", "-")
            lines.append(f"- [{_escape_markdown(section.title)}](#{anchor})")
        lines.append("")

        for section in report.sections:
            lines.append(_render_section(section))

        if include_charts:
            lines.append("## Charts\n")
            for name, figure in build_all_charts(report).items():
                image_bytes = safe_encode(self._chart_image_encoder, figure, chart_name=name)
                title = name.replace("_", " ").title()
                if image_bytes is None:
                    lines.append(f"### {title}\n\n_Chart rendering unavailable._\n")
                    continue
                data_uri = self._asset_manager.to_data_uri(image_bytes, mime_type="image/png")
                lines.append(f"### {title}\n\n![{title}]({data_uri})\n")

        return "\n".join(lines)

    def render_bytes(self, report: GeneratedReport, *, include_charts: bool = True) -> bytes:
        return self.render(report, include_charts=include_charts).encode("utf-8")
