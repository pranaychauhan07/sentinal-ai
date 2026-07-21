"""Unit tests for core/reporting/asset_manager.py."""

from __future__ import annotations

import base64

import pytest

from core.reporting.asset_manager import AssetManager, from_data_uri
from core.reporting.exceptions import AssetEmbeddingError

pytestmark = pytest.mark.unit

_TINY_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
)


def test_to_data_uri_round_trips_through_from_data_uri() -> None:
    manager = AssetManager()
    uri = manager.to_data_uri(_TINY_PNG, mime_type="image/png")
    assert uri.startswith("data:image/png;base64,")
    decoded = from_data_uri(uri)
    assert decoded == _TINY_PNG


def test_prepare_binary_returns_validated_bytes() -> None:
    manager = AssetManager()
    assert manager.prepare_binary(_TINY_PNG, mime_type="image/png") == _TINY_PNG


def test_rejects_unsupported_mime_type() -> None:
    manager = AssetManager()
    with pytest.raises(AssetEmbeddingError):
        manager.to_data_uri(_TINY_PNG, mime_type="application/octet-stream")


def test_rejects_oversized_asset() -> None:
    manager = AssetManager(max_asset_bytes=10)
    with pytest.raises(AssetEmbeddingError):
        manager.to_data_uri(_TINY_PNG, mime_type="image/png")


def test_from_data_uri_returns_none_for_malformed_uri() -> None:
    assert from_data_uri("not-a-data-uri") is None
