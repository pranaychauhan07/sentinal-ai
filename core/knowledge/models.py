"""Typed contracts for the Knowledge Layer (`context/01_blueprint.md` §4).

No knowledge data is populated by this module — per this milestone's
explicit scope, these are the shapes future MITRE/OWASP/threat-intel/
playbook/detection-rule/investigation-template content will be loaded into,
not the content itself (ADR-0010).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class KnowledgeSourceType(StrEnum):
    """The closed set of knowledge domains blueprint §4/§10 names. Adding a
    new source type is a deliberate, reviewed change to this enum — never an
    ad hoc string scattered across call sites (constitution §2, "Enums")."""

    MITRE_ATTACK = "mitre_attack"
    OWASP_TOP10 = "owasp_top10"
    THREAT_INTELLIGENCE = "threat_intelligence"
    SECURITY_PLAYBOOK = "security_playbook"
    DETECTION_RULE = "detection_rule"
    INVESTIGATION_TEMPLATE = "investigation_template"


class KnowledgeDocument(BaseModel):
    """One retrievable unit of knowledge — a MITRE technique entry, an OWASP
    category, a playbook step, a detection rule, a template section. The
    single shape every `KnowledgeSource` returns, regardless of which
    taxonomy it wraps, so `core/memory/context_builder.py`-style downstream
    consumers don't need one code path per source type.
    """

    model_config = ConfigDict(frozen=True)

    id: str
    source_type: KnowledgeSourceType
    title: str
    content: str
    tags: tuple[str, ...] = ()
    metadata: dict[str, Any] = Field(default_factory=dict)


class KnowledgeQuery(BaseModel):
    """Search parameters accepted by `KnowledgeSource.search` /
    `KnowledgeRetriever.retrieve`."""

    model_config = ConfigDict(frozen=True)

    text: str
    source_types: tuple[KnowledgeSourceType, ...] = ()
    limit: int = Field(default=10, gt=0, le=200)


class KnowledgeSearchResult(BaseModel):
    """One scored match from a knowledge search — mirrors
    `core.memory.models.MemoryQueryResult`'s shape deliberately, so a
    `ContextBuilder`-style caller can treat memory and knowledge results
    uniformly if a future milestone chooses to merge them."""

    model_config = ConfigDict(frozen=True)

    document: KnowledgeDocument
    score: float = Field(ge=0.0, le=1.0)
