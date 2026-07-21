"""Loads `data/knowledge/security_best_practices.yaml` and
`data/knowledge/incident_response_guidance.yaml` into typed records — local
files only, no network call.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from core.knowledge.exceptions import KnowledgeDataError
from core.knowledge.playbooks.models import BestPracticeEntry, IncidentResponsePhaseGuidance


def _load_yaml(path: Path) -> dict[str, object]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise KnowledgeDataError(
            f"Could not read playbook knowledge data at {path}: {exc}",
            details={"path": str(path)},
        ) from exc
    except yaml.YAMLError as exc:
        raise KnowledgeDataError(
            f"Malformed YAML in playbook knowledge data at {path}: {exc}",
            details={"path": str(path)},
        ) from exc
    if not isinstance(raw, dict):
        raise KnowledgeDataError(
            f"Playbook knowledge data at {path} is not a mapping.", details={"path": str(path)}
        )
    return raw


def load_best_practices(path: Path) -> tuple[BestPracticeEntry, ...]:
    raw = _load_yaml(path)
    entries = raw.get("practices")
    if not isinstance(entries, list):
        raise KnowledgeDataError(
            f"Best-practice data at {path} is missing a top-level 'practices' list.",
            details={"path": str(path)},
        )
    try:
        return tuple(BestPracticeEntry.model_validate(entry) for entry in entries)
    except Exception as exc:  # noqa: BLE001 - a malformed row is a data error, not a runtime bug
        raise KnowledgeDataError(
            f"Malformed best-practice entry in {path}: {exc}", details={"path": str(path)}
        ) from exc


def load_incident_response_guidance(path: Path) -> tuple[IncidentResponsePhaseGuidance, ...]:
    raw = _load_yaml(path)
    entries = raw.get("phases")
    if not isinstance(entries, list):
        raise KnowledgeDataError(
            f"Incident-response guidance at {path} is missing a top-level 'phases' list.",
            details={"path": str(path)},
        )
    try:
        return tuple(IncidentResponsePhaseGuidance.model_validate(entry) for entry in entries)
    except Exception as exc:  # noqa: BLE001 - a malformed row is a data error, not a runtime bug
        raise KnowledgeDataError(
            f"Malformed incident-response phase entry in {path}: {exc}",
            details={"path": str(path)},
        ) from exc
