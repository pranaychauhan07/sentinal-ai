"""`ChartImageEncoder` — rasterizes a Plotly figure to PNG bytes for the
static-format renderers (`pdf_renderer.py`, `docx_renderer.py`; HTML export
embeds charts as live, interactive Plotly JS instead, via
`html_renderer.py`, so it never needs this module).

A `Protocol` (mirroring `core.conversation.llm_provider.ChatModelProvider`'s
identical "define the shape, inject a concrete implementation" pattern,
constitution §2's "Dependency injection") plus one concrete implementation,
`KaleidoChartImageEncoder`, backed by Plotly's `kaleido` package (a
headless-Chrome-driven static image exporter — the standard, official way
to rasterize a Plotly figure; requirements.txt justifies the new
dependency). Kept behind this thin adapter (constitution §5, "External
APIs... a thin adapter... this is what makes the adapter mockable in unit
tests") for two reasons: real chart rendering costs ~1-2 seconds per call
(a real subprocess/browser round trip) so unit tests inject a fast fake
instead of paying that cost per test, and a deployment without a working
Chrome/Kaleido install degrades gracefully (see `safe_encode` below) rather
than making chart embedding a hard dependency of PDF/DOCX export.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

import plotly.graph_objects as go

from core.logging import get_logger
from core.reporting.exceptions import ChartRenderingError

_logger = get_logger(__name__)

DEFAULT_CHART_WIDTH = 900
DEFAULT_CHART_HEIGHT = 500


@runtime_checkable
class ChartImageEncoder(Protocol):
    """Contract every concrete chart-rasterization backend implements."""

    def encode(
        self,
        figure: go.Figure,
        *,
        width: int = DEFAULT_CHART_WIDTH,
        height: int = DEFAULT_CHART_HEIGHT,
    ) -> bytes: ...


class KaleidoChartImageEncoder:
    """The production `ChartImageEncoder` — Plotly's own `Figure.to_image`,
    which delegates to the `kaleido` package."""

    def encode(
        self,
        figure: go.Figure,
        *,
        width: int = DEFAULT_CHART_WIDTH,
        height: int = DEFAULT_CHART_HEIGHT,
    ) -> bytes:
        try:
            result = figure.to_image(format="png", width=width, height=height)
        except Exception as exc:  # noqa: BLE001 - any Kaleido/Chrome failure, see safe_encode
            raise ChartRenderingError(
                f"Failed to rasterize chart: {exc}", details={"error": str(exc)}
            ) from exc
        return bytes(result)


def safe_encode(encoder: ChartImageEncoder, figure: go.Figure, *, chart_name: str) -> bytes | None:
    """Never raises: a chart-rendering failure (e.g. no Chrome available in
    this deployment) degrades to "chart omitted," logged at `WARNING`
    (constitution §8), rather than aborting the entire PDF/DOCX export
    (constitution §1.7, "fail gracefully")."""
    try:
        return encoder.encode(figure)
    except ChartRenderingError as exc:
        _logger.warning("chart_render_degraded", chart_name=chart_name, error=exc.message)
        return None
