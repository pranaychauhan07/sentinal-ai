"""Unit tests for core/conversation/tool_selection.py."""

from __future__ import annotations

import pytest

from core.conversation.models import EvidenceCategory
from core.conversation.tool_selection import ToolSelectionEngine


@pytest.mark.unit
def test_select_routes_ioc_keyword_to_ioc_category() -> None:
    engine = ToolSelectionEngine()
    selection = engine.select("What IOCs were found in this case?")
    assert EvidenceCategory.IOC in selection.categories


@pytest.mark.unit
def test_select_routes_mitre_keyword_to_mitre_category() -> None:
    engine = ToolSelectionEngine()
    selection = engine.select("Which MITRE ATT&CK technique applies here?")
    assert EvidenceCategory.MITRE_MAPPING in selection.categories


@pytest.mark.unit
def test_select_routes_best_practice_keyword_to_knowledge_category() -> None:
    engine = ToolSelectionEngine()
    selection = engine.select("What is the OWASP best practice for this?")
    assert EvidenceCategory.KNOWLEDGE in selection.categories


@pytest.mark.unit
def test_select_routes_similar_case_keyword_to_similar_case_category() -> None:
    engine = ToolSelectionEngine()
    selection = engine.select("Have we seen this before in a similar case?")
    assert EvidenceCategory.SIMILAR_CASE in selection.categories


@pytest.mark.unit
def test_select_falls_back_to_all_categories_when_no_keyword_matches() -> None:
    engine = ToolSelectionEngine()
    selection = engine.select("tell me something interesting")
    assert set(selection.categories) == set(EvidenceCategory)


@pytest.mark.unit
def test_select_is_deterministic_for_the_same_question() -> None:
    engine = ToolSelectionEngine()
    first = engine.select("explain finding severity")
    second = engine.select("explain finding severity")
    assert first == second
