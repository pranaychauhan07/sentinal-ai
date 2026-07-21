"""Typed contract for one parsed
`data/knowledge/detection_engineering_guidance.yaml` entry."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class DetectionPrinciple(BaseModel):
    """One detection-engineering guidance principle — reference content
    only; structurally independent of `core/findings/mapping_rules.py`
    (this project's actual MITRE mapping rule engine, untouched by this
    package)."""

    model_config = ConfigDict(frozen=True)

    id: str
    title: str
    guidance: str
