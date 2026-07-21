"""Typed contract for one parsed `data/knowledge/owasp_top10.yaml` entry."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class OwaspCategory(BaseModel):
    """One OWASP Top 10 category — reference content only (constitution
    §1.9: no risk scoring or detection logic lives here, that stays in the
    structurally independent `core/owasp_security`/`core/owasp_web`)."""

    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    description: str
    remediation: str
