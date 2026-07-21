"""Loads `data/knowledge/owasp_top10.yaml` into typed `OwaspCategory`
records — local file only, no network call, mirroring
`core.knowledge.mitre.loader`'s "vendored, offline" convention.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from core.knowledge.exceptions import KnowledgeDataError
from core.knowledge.owasp.models import OwaspCategory


def load_owasp_categories(path: Path) -> tuple[OwaspCategory, ...]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise KnowledgeDataError(
            f"Could not read OWASP knowledge data at {path}: {exc}", details={"path": str(path)}
        ) from exc
    except yaml.YAMLError as exc:
        raise KnowledgeDataError(
            f"Malformed YAML in OWASP knowledge data at {path}: {exc}", details={"path": str(path)}
        ) from exc

    if not isinstance(raw, dict) or not isinstance(raw.get("categories"), list):
        raise KnowledgeDataError(
            f"OWASP knowledge data at {path} is missing a top-level 'categories' list.",
            details={"path": str(path)},
        )

    categories: list[OwaspCategory] = []
    for entry in raw["categories"]:
        try:
            categories.append(OwaspCategory.model_validate(entry))
        except Exception as exc:  # noqa: BLE001 - a single malformed row degrades, not crashes
            raise KnowledgeDataError(
                f"Malformed OWASP category entry in {path}: {exc}",
                details={"path": str(path), "entry": entry},
            ) from exc
    return tuple(categories)
