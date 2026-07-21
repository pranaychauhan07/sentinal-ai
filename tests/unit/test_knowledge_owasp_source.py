"""Unit tests for core/knowledge/owasp/{models,loader,source}.py."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from core.knowledge.exceptions import KnowledgeDataError
from core.knowledge.interfaces import KnowledgeSource
from core.knowledge.models import KnowledgeQuery, KnowledgeSourceType
from core.knowledge.owasp.loader import load_owasp_categories
from core.knowledge.owasp.models import OwaspCategory
from core.knowledge.owasp.source import OwaspTop10Source

pytestmark = pytest.mark.unit


def _categories() -> tuple[OwaspCategory, ...]:
    return (
        OwaspCategory(
            id="A03:2021",
            name="Injection",
            description="User-supplied data is interpreted as part of a command or query.",
            remediation="Use parameterized queries.",
        ),
    )


def test_owasp_top10_source_satisfies_knowledge_source_protocol() -> None:
    assert isinstance(OwaspTop10Source(_categories()), KnowledgeSource)


def test_owasp_top10_source_type() -> None:
    assert OwaspTop10Source(_categories()).source_type == KnowledgeSourceType.OWASP_TOP10.value


def test_get_returns_document_by_id() -> None:
    document = OwaspTop10Source(_categories()).get("A03:2021")
    assert document is not None
    assert document.title == "Injection"
    assert "parameterized queries" in document.content.lower()


def test_get_returns_none_for_unknown_id() -> None:
    assert OwaspTop10Source(_categories()).get("A99:2021") is None


def test_search_matches_on_title_and_content() -> None:
    results = OwaspTop10Source(_categories()).search(KnowledgeQuery(text="sql injection command"))
    assert results
    assert results[0].document.id == "A03:2021"


def test_search_returns_empty_for_no_match() -> None:
    results = OwaspTop10Source(_categories()).search(KnowledgeQuery(text="unrelated zzz"))
    assert results == []


def test_load_owasp_categories_from_real_vendored_data_file() -> None:
    path = Path("data/knowledge/owasp_top10.yaml")
    categories = load_owasp_categories(path)
    assert len(categories) == 10
    assert {c.id for c in categories} >= {"A01:2021", "A03:2021", "A10:2021"}


def test_load_owasp_categories_missing_file_raises() -> None:
    with pytest.raises(KnowledgeDataError):
        load_owasp_categories(Path("data/knowledge/does_not_exist.yaml"))


def test_load_owasp_categories_malformed_yaml_raises(tmp_path: Path) -> None:
    bad_file = tmp_path / "bad.yaml"
    bad_file.write_text("not_categories: []", encoding="utf-8")
    with pytest.raises(KnowledgeDataError):
        load_owasp_categories(bad_file)


def test_load_owasp_categories_malformed_entry_raises(tmp_path: Path) -> None:
    bad_file = tmp_path / "bad.yaml"
    bad_file.write_text(
        yaml.safe_dump({"categories": [{"id": "A01:2021", "name": "Missing fields"}]}),
        encoding="utf-8",
    )
    with pytest.raises(KnowledgeDataError):
        load_owasp_categories(bad_file)
