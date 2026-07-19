"""Unit tests for core/knowledge/mitre/source.py — MitreAttackSource's
`KnowledgeSource` Protocol compliance."""

from __future__ import annotations

import pytest

from core.knowledge.interfaces import KnowledgeSource
from core.knowledge.mitre.models import MitreDataset, MitreTactic, MitreTechnique
from core.knowledge.mitre.source import MitreAttackSource
from core.knowledge.models import KnowledgeQuery, KnowledgeSourceType

VERSION = "1.0-test"


def _dataset() -> MitreDataset:
    return MitreDataset(
        attack_spec_version=VERSION,
        tactics=(
            MitreTactic(
                tactic_id="TA0006",
                name="Credential Access",
                shortname="credential-access",
                description="Stealing account names and passwords.",
                attack_spec_version=VERSION,
            ),
        ),
        techniques=(
            MitreTechnique(
                technique_id="T1110",
                name="Brute Force",
                description="Guessing passwords to gain access to accounts.",
                tactic_shortnames=("credential-access",),
                attack_spec_version=VERSION,
            ),
        ),
    )


@pytest.mark.unit
def test_mitre_attack_source_satisfies_knowledge_source_protocol() -> None:
    source = MitreAttackSource(_dataset())
    assert isinstance(source, KnowledgeSource)


@pytest.mark.unit
def test_mitre_attack_source_source_type() -> None:
    source = MitreAttackSource(_dataset())
    assert source.source_type == KnowledgeSourceType.MITRE_ATTACK.value


@pytest.mark.unit
def test_get_returns_document_by_business_id() -> None:
    source = MitreAttackSource(_dataset())
    document = source.get("T1110")
    assert document is not None
    assert document.title == "Brute Force"
    assert document.source_type is KnowledgeSourceType.MITRE_ATTACK


@pytest.mark.unit
def test_get_returns_none_for_unknown_id() -> None:
    source = MitreAttackSource(_dataset())
    assert source.get("T9999") is None


@pytest.mark.unit
def test_search_matches_on_title_and_content() -> None:
    source = MitreAttackSource(_dataset())
    results = source.search(KnowledgeQuery(text="brute force passwords"))
    assert results
    assert results[0].document.id == "T1110"
    assert results[0].score > 0.0


@pytest.mark.unit
def test_search_returns_empty_for_no_match() -> None:
    source = MitreAttackSource(_dataset())
    results = source.search(KnowledgeQuery(text="completely unrelated query zzz"))
    assert results == []


@pytest.mark.unit
def test_search_respects_limit() -> None:
    source = MitreAttackSource(_dataset())
    results = source.search(KnowledgeQuery(text="access", limit=1))
    assert len(results) <= 1
