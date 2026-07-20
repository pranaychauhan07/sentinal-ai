"""Unit tests for core/owasp_web/category_mapper.py."""

from __future__ import annotations

import pytest

from core.owasp_web.category_mapper import OwaspCategoryMapper
from core.owasp_web.models import OwaspCategory

pytestmark = pytest.mark.unit


def test_describe_returns_info_for_every_category() -> None:
    mapper = OwaspCategoryMapper()
    for category in OwaspCategory:
        info = mapper.describe(category)
        assert info.category == category
        assert info.name
        assert info.description


def test_all_categories_returns_ten_entries() -> None:
    assert len(OwaspCategoryMapper().all_categories()) == 10


def test_a01_name_matches_official_owasp_label() -> None:
    info = OwaspCategoryMapper().describe(OwaspCategory.A01_BROKEN_ACCESS_CONTROL)
    assert "Broken Access Control" in info.name
