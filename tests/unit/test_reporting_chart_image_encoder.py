"""Unit tests for core/reporting/chart_image_encoder.py.

Never invokes the real Kaleido/Chrome backend (constitution §11, "mock at
the boundary, not the internals") — `Figure.to_image` is monkeypatched at
the instance level so these tests stay fast and deterministic; the real
Kaleido path is exercised only by the manual smoke test recorded in
docs/adr/0026-report-export-framework.md, not by the unit suite.
"""

from __future__ import annotations

import plotly.graph_objects as go
import pytest

from core.reporting.chart_image_encoder import (
    ChartImageEncoder,
    KaleidoChartImageEncoder,
    safe_encode,
)
from core.reporting.exceptions import ChartRenderingError

pytestmark = pytest.mark.unit


def _figure() -> go.Figure:
    return go.Figure(data=[go.Bar(x=["a"], y=[1])])


def test_kaleido_encoder_satisfies_protocol() -> None:
    assert isinstance(KaleidoChartImageEncoder(), ChartImageEncoder)


def test_kaleido_encoder_returns_bytes_on_success() -> None:
    figure = _figure()
    figure.to_image = lambda **_kwargs: b"fake-png-bytes"  # type: ignore[method-assign]
    encoder = KaleidoChartImageEncoder()
    assert encoder.encode(figure) == b"fake-png-bytes"


def test_kaleido_encoder_wraps_failure_as_chart_rendering_error() -> None:
    figure = _figure()

    def _boom(**_kwargs: object) -> bytes:
        raise RuntimeError("no chrome available")

    figure.to_image = _boom  # type: ignore[method-assign]
    encoder = KaleidoChartImageEncoder()
    with pytest.raises(ChartRenderingError):
        encoder.encode(figure)


def test_safe_encode_returns_bytes_on_success() -> None:
    figure = _figure()
    figure.to_image = lambda **_kwargs: b"fake-png-bytes"  # type: ignore[method-assign]
    result = safe_encode(KaleidoChartImageEncoder(), figure, chart_name="test_chart")
    assert result == b"fake-png-bytes"


def test_safe_encode_degrades_to_none_on_failure() -> None:
    figure = _figure()

    def _boom(**_kwargs: object) -> bytes:
        raise RuntimeError("no chrome available")

    figure.to_image = _boom  # type: ignore[method-assign]
    result = safe_encode(KaleidoChartImageEncoder(), figure, chart_name="test_chart")
    assert result is None
