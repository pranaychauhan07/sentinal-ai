"""Unit tests for core/knowledge/detection/{models,loader,source}.py."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.knowledge.detection.loader import load_detection_principles
from core.knowledge.detection.models import DetectionPrinciple
from core.knowledge.detection.source import DetectionRuleSource
from core.knowledge.exceptions import KnowledgeDataError
from core.knowledge.interfaces import KnowledgeSource
from core.knowledge.models import KnowledgeQuery, KnowledgeSourceType

pytestmark = pytest.mark.unit


def _principles() -> tuple[DetectionPrinciple, ...]:
    return (
        DetectionPrinciple(
            id="DE-04",
            title="Tune for False-Positive Rate",
            guidance="Run new detections silently before wide deployment.",
        ),
    )


def test_detection_rule_source_satisfies_knowledge_source_protocol() -> None:
    assert isinstance(DetectionRuleSource(_principles()), KnowledgeSource)


def test_source_type() -> None:
    assert (
        DetectionRuleSource(_principles()).source_type == KnowledgeSourceType.DETECTION_RULE.value
    )


def test_get_returns_document_by_id() -> None:
    document = DetectionRuleSource(_principles()).get("DE-04")
    assert document is not None
    assert document.title == "Tune for False-Positive Rate"


def test_search_matches_on_guidance_text() -> None:
    results = DetectionRuleSource(_principles()).search(
        KnowledgeQuery(text="false positive tuning")
    )
    assert results
    assert results[0].document.id == "DE-04"


def test_load_detection_principles_from_real_vendored_data_file() -> None:
    principles = load_detection_principles(
        Path("data/knowledge/detection_engineering_guidance.yaml")
    )
    assert len(principles) == 7
    assert {p.id for p in principles} >= {"DE-01", "DE-07"}


def test_load_detection_principles_missing_file_raises() -> None:
    with pytest.raises(KnowledgeDataError):
        load_detection_principles(Path("data/knowledge/does_not_exist.yaml"))


def test_load_detection_principles_malformed_yaml_raises(tmp_path: Path) -> None:
    bad_file = tmp_path / "bad.yaml"
    bad_file.write_text("wrong_key: []", encoding="utf-8")
    with pytest.raises(KnowledgeDataError):
        load_detection_principles(bad_file)
