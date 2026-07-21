"""Loads `data/knowledge/detection_engineering_guidance.yaml` into typed
`DetectionPrinciple` records — local file only, no network call.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from core.knowledge.detection.models import DetectionPrinciple
from core.knowledge.exceptions import KnowledgeDataError


def load_detection_principles(path: Path) -> tuple[DetectionPrinciple, ...]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise KnowledgeDataError(
            f"Could not read detection-engineering knowledge data at {path}: {exc}",
            details={"path": str(path)},
        ) from exc
    except yaml.YAMLError as exc:
        raise KnowledgeDataError(
            f"Malformed YAML in detection-engineering knowledge data at {path}: {exc}",
            details={"path": str(path)},
        ) from exc

    if not isinstance(raw, dict) or not isinstance(raw.get("principles"), list):
        raise KnowledgeDataError(
            f"Detection-engineering knowledge data at {path} is missing a top-level "
            "'principles' list.",
            details={"path": str(path)},
        )

    try:
        return tuple(DetectionPrinciple.model_validate(entry) for entry in raw["principles"])
    except Exception as exc:  # noqa: BLE001 - a malformed row is a data error, not a runtime bug
        raise KnowledgeDataError(
            f"Malformed detection principle entry in {path}: {exc}", details={"path": str(path)}
        ) from exc
