"""PDF Renderer — the task's named "PDF Renderer".

Built directly on ReportLab's Platypus flowable model (`SimpleDocTemplate`,
`Paragraph`, `Table`, `Image`) driven straight from `GeneratedReport` —
never an HTML-to-PDF conversion (this codebase has no such library as a
dependency; blueprint §5 names "Jinja2 -> ReportLab" as the reporting
stack, which this framework satisfies as "Jinja2 for the HTML/Markdown
path, ReportLab for the PDF path," both against the same `GeneratedReport`
source of truth, rather than literally piping HTML through ReportLab, which
ReportLab cannot do without a third dependency this project does not carry).

Header/footer/page-numbering uses ReportLab's standard "NumberedCanvas"
recipe (`_NumberedCanvas` below) — a two-pass technique (every page is
drawn once to learn the total page count, then a second pass stamps
"Page X of N" on each) that is the accepted, documented way to get a total
page count in ReportLab, since a single top-to-bottom pass can't know how
many pages follow the current one.
"""

from __future__ import annotations

import io

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas as reportlab_canvas
from reportlab.platypus import (
    Image,
    ListFlowable,
    ListItem,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from core.reporting.asset_manager import AssetManager, from_data_uri
from core.reporting.chart_image_encoder import (
    ChartImageEncoder,
    KaleidoChartImageEncoder,
    safe_encode,
)
from core.reporting.charts import build_all_charts
from core.reporting.models import GeneratedReport, ReportSection
from core.reporting.theme import ReportTheme, resolve_theme

_PAGE_SIZE = LETTER
_MARGIN = 0.75 * inch


class _NumberedCanvas(reportlab_canvas.Canvas):  # type: ignore[misc]  # reportlab ships no stubs
    """ReportLab's standard two-pass page-numbering canvas — buffers every
    page's drawing operations, then replays them once the total page count
    is known so each page can render "Page X of N", not just "Page X"."""

    def __init__(self, *args: object, theme: ReportTheme, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self._saved_page_states: list[dict[str, object]] = []
        self._theme = theme

    def showPage(self) -> None:  # noqa: N802 - overrides reportlab.Canvas's own camelCase API
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        total_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_footer(total_pages)
            super().showPage()
        super().save()

    def _draw_footer(self, total_pages: int) -> None:
        if not self._theme.page_numbering:
            return
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor(self._theme.secondary_color))
        page_width = _PAGE_SIZE[0]
        self.drawRightString(
            page_width - _MARGIN, 0.5 * inch, f"Page {self._pageNumber} of {total_pages}"
        )
        if self._theme.footer_text:
            self.drawString(_MARGIN, 0.5 * inch, self._theme.footer_text)


def _styles(theme: ReportTheme) -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    primary = colors.HexColor(theme.primary_color)
    return {
        "title": ParagraphStyle("ReportTitle", parent=base["Title"], textColor=primary),
        "heading": ParagraphStyle("ReportHeading", parent=base["Heading2"], textColor=primary),
        "subheading": ParagraphStyle("ReportSubheading", parent=base["Heading3"]),
        "body": base["BodyText"],
        "meta": ParagraphStyle(
            "ReportMeta", parent=base["BodyText"], textColor=colors.HexColor(theme.secondary_color)
        ),
    }


def _value_flowables(
    value: object, styles: dict[str, ParagraphStyle], *, depth: int = 0
) -> list[object]:
    if isinstance(value, dict):
        items = []
        for key, item in value.items():
            child = _value_flowables(item, styles, depth=depth + 1)
            if len(child) == 1 and isinstance(child[0], Paragraph):
                items.append(ListItem(Paragraph(f"<b>{key}:</b> {_escape(item)}", styles["body"])))
            else:
                items.append(ListItem(Paragraph(f"<b>{key}:</b>", styles["body"])))
                items.extend(ListItem(f) for f in child)
        return (
            [ListFlowable(items, bulletType="bullet")]
            if items
            else [Paragraph("(none)", styles["body"])]
        )
    if isinstance(value, list | tuple):
        if not value:
            return [Paragraph("(none)", styles["body"])]
        if all(isinstance(item, dict) for item in value):
            return [_table_flowable(list(value), styles)]
        return [
            ListFlowable(
                [ListItem(Paragraph(_escape(item), styles["body"])) for item in value],
                bulletType="bullet",
            )
        ]
    return [Paragraph(_escape(value), styles["body"])]


def _escape(value: object) -> str:
    text = str(value)
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _table_flowable(rows: list[dict[str, object]], styles: dict[str, ParagraphStyle]) -> Table:
    headers = list(rows[0].keys())
    data = [[Paragraph(f"<b>{h}</b>", styles["body"]) for h in headers]]
    for row in rows:
        data.append([Paragraph(_escape(row.get(h, "")), styles["body"]) for h in headers])
    table = Table(data, repeatRows=1, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    return table


def _section_flowables(section: ReportSection, styles: dict[str, ParagraphStyle]) -> list[object]:
    flowables: list[object] = [Paragraph(section.title, styles["heading"])]
    if section.is_empty:
        flowables.append(Paragraph("<i>No data available for this section.</i>", styles["body"]))
    else:
        flowables.extend(_value_flowables(section.content, styles))
    flowables.append(Spacer(1, 0.2 * inch))
    return flowables


class PDFReportRenderer:
    def __init__(
        self,
        *,
        asset_manager: AssetManager | None = None,
        chart_image_encoder: ChartImageEncoder | None = None,
    ) -> None:
        self._asset_manager = asset_manager or AssetManager()
        self._chart_image_encoder = chart_image_encoder or KaleidoChartImageEncoder()

    def render(
        self,
        report: GeneratedReport,
        *,
        theme: ReportTheme | str | None = None,
        include_charts: bool = True,
    ) -> bytes:
        resolved_theme = resolve_theme(theme)
        styles = _styles(resolved_theme)
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=_PAGE_SIZE,
            leftMargin=_MARGIN,
            rightMargin=_MARGIN,
            topMargin=_MARGIN,
            bottomMargin=_MARGIN,
            title=report.title,
        )

        story: list[object] = []
        if resolved_theme.logo_data_uri:
            logo_bytes = from_data_uri(resolved_theme.logo_data_uri)
            if logo_bytes is not None:
                story.append(Image(io.BytesIO(logo_bytes), width=1.5 * inch, height=0.75 * inch))
                story.append(Spacer(1, 0.15 * inch))
        if resolved_theme.organization_name:
            story.append(Paragraph(resolved_theme.organization_name, styles["meta"]))
        story.append(Paragraph(report.title, styles["title"]))
        report_type_text = _escape(report.report_type.value)
        generated_text = _escape(report.generated_at.isoformat())
        story.append(
            Paragraph(
                f"Case: {_escape(report.case_id)} &middot; Type: {report_type_text} "
                f"&middot; Generated: {generated_text}",
                styles["meta"],
            )
        )
        status = "Degraded" if report.degraded else "Complete"
        story.append(
            Paragraph(
                f"Confidence: {report.confidence * 100:.0f}% &middot; Status: {status}",
                styles["meta"],
            )
        )
        story.append(Spacer(1, 0.3 * inch))

        for section in report.sections:
            story.extend(_section_flowables(section, styles))

        if include_charts:
            story.append(PageBreak())
            story.append(Paragraph("Charts", styles["heading"]))
            for name, figure in build_all_charts(report).items():
                image_bytes = safe_encode(self._chart_image_encoder, figure, chart_name=name)
                title = name.replace("_", " ").title()
                story.append(Paragraph(title, styles["subheading"]))
                if image_bytes is None:
                    story.append(Paragraph("<i>Chart rendering unavailable.</i>", styles["body"]))
                    continue
                validated = self._asset_manager.prepare_binary(image_bytes, mime_type="image/png")
                image_stream = io.BytesIO(validated)
                story.append(Image(image_stream, width=6.5 * inch, height=3.6 * inch))
                story.append(Spacer(1, 0.2 * inch))

        def _make_canvas(*args: object, **kwargs: object) -> _NumberedCanvas:
            return _NumberedCanvas(*args, theme=resolved_theme, **kwargs)

        doc.build(story, canvasmaker=_make_canvas)
        return buffer.getvalue()
