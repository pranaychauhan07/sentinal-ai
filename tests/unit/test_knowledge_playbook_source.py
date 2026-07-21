"""Unit tests for core/knowledge/playbooks/{models,loader,source}.py."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.knowledge.exceptions import KnowledgeDataError
from core.knowledge.interfaces import KnowledgeSource
from core.knowledge.models import KnowledgeQuery, KnowledgeSourceType
from core.knowledge.playbooks.loader import load_best_practices, load_incident_response_guidance
from core.knowledge.playbooks.models import BestPracticeEntry, IncidentResponsePhaseGuidance
from core.knowledge.playbooks.source import SecurityPlaybookSource

pytestmark = pytest.mark.unit


def _source() -> SecurityPlaybookSource:
    return SecurityPlaybookSource(
        best_practices=(
            BestPracticeEntry(
                id="BP-01",
                title="Least Privilege",
                category="identity_and_access",
                guidance="Grant only the permissions required.",
            ),
        ),
        incident_response_phases=(
            IncidentResponsePhaseGuidance(
                id="IR-CONTAIN",
                phase="Containment",
                guidance="Isolate affected hosts before remediation.",
            ),
        ),
    )


def test_security_playbook_source_satisfies_knowledge_source_protocol() -> None:
    assert isinstance(_source(), KnowledgeSource)


def test_source_type() -> None:
    assert _source().source_type == KnowledgeSourceType.SECURITY_PLAYBOOK.value


def test_get_returns_best_practice_by_id() -> None:
    document = _source().get("BP-01")
    assert document is not None
    assert document.title == "Least Privilege"


def test_get_returns_ir_phase_by_id() -> None:
    document = _source().get("IR-CONTAIN")
    assert document is not None
    assert document.title == "Containment"


def test_search_matches_across_both_content_types() -> None:
    results = _source().search(KnowledgeQuery(text="isolate affected hosts containment"))
    assert results
    assert results[0].document.id == "IR-CONTAIN"


def test_load_best_practices_from_real_vendored_data_file() -> None:
    practices = load_best_practices(Path("data/knowledge/security_best_practices.yaml"))
    assert len(practices) == 10
    assert {p.id for p in practices} >= {"BP-01", "BP-10"}


def test_load_incident_response_guidance_from_real_vendored_data_file() -> None:
    phases = load_incident_response_guidance(Path("data/knowledge/incident_response_guidance.yaml"))
    assert len(phases) == 6
    assert {p.id for p in phases} == {
        "IR-PREP",
        "IR-DETECT",
        "IR-CONTAIN",
        "IR-ERADICATE",
        "IR-RECOVER",
        "IR-POSTINCIDENT",
    }


def test_load_best_practices_missing_file_raises() -> None:
    with pytest.raises(KnowledgeDataError):
        load_best_practices(Path("data/knowledge/does_not_exist.yaml"))


def test_load_incident_response_guidance_malformed_yaml_raises(tmp_path: Path) -> None:
    bad_file = tmp_path / "bad.yaml"
    bad_file.write_text("phases: not-a-list", encoding="utf-8")
    with pytest.raises(KnowledgeDataError):
        load_incident_response_guidance(bad_file)
