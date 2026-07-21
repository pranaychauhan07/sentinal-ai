"""Unit tests for core/knowledge/bootstrap.py."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.config import get_settings
from core.knowledge.bootstrap import register_default_knowledge_sources
from core.knowledge.models import KnowledgeQuery, KnowledgeSourceType
from core.knowledge.registry import KnowledgeSourceRegistry

pytestmark = pytest.mark.unit


def test_registers_all_four_sources_against_real_vendored_data() -> None:
    registry = KnowledgeSourceRegistry()
    register_default_knowledge_sources(registry, get_settings())
    registered = set(registry.list_source_types())
    assert registered == {
        KnowledgeSourceType.MITRE_ATTACK,
        KnowledgeSourceType.OWASP_TOP10,
        KnowledgeSourceType.SECURITY_PLAYBOOK,
        KnowledgeSourceType.DETECTION_RULE,
    }


def test_registered_sources_are_independently_searchable() -> None:
    registry = KnowledgeSourceRegistry()
    register_default_knowledge_sources(registry, get_settings())

    owasp = registry.get(KnowledgeSourceType.OWASP_TOP10)
    assert owasp.search(KnowledgeQuery(text="broken access control"))

    playbook = registry.get(KnowledgeSourceType.SECURITY_PLAYBOOK)
    assert playbook.search(KnowledgeQuery(text="multi-factor authentication"))

    detection = registry.get(KnowledgeSourceType.DETECTION_RULE)
    assert detection.search(KnowledgeQuery(text="behavior based detection"))


def test_one_missing_data_file_does_not_block_the_others(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = get_settings().model_copy(
        update={"owasp_top10_data_path": Path("data/knowledge/does_not_exist.yaml")}
    )
    registry = KnowledgeSourceRegistry()
    register_default_knowledge_sources(registry, settings)

    registered = set(registry.list_source_types())
    assert KnowledgeSourceType.OWASP_TOP10 not in registered
    assert KnowledgeSourceType.MITRE_ATTACK in registered
    assert KnowledgeSourceType.SECURITY_PLAYBOOK in registered
    assert KnowledgeSourceType.DETECTION_RULE in registered
