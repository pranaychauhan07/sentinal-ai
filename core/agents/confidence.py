"""Confidence Score Interface — the one typed representation of "how sure is
this result" every agent output and downstream consumer (UI, reports) shares.

Backs context/03_engineering_constitution.md §4.6 ("Confidence scoring...
mandatory on every output") with a single reusable value object instead of
every agent inventing its own float-vs-label convention.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator

#: Deterministic-parser-backed findings default here (constitution §4.6).
DETERMINISTIC_CONFIDENCE = 1.0
#: LLM-fallback-derived findings are capped below this by convention.
LLM_FALLBACK_CONFIDENCE_CEILING = 0.7


class ConfidenceLevel(StrEnum):
    """Coarse bucket a :class:`ConfidenceScore` falls into — what the UI/report
    layer actually renders (a badge), rather than a raw float."""

    CERTAIN = "certain"  # deterministic, parser- or tool-backed
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"  # insufficient basis to assess at all


def classify_confidence(value: float) -> ConfidenceLevel:
    """Pure, deterministic bucketing of a 0.0-1.0 score into a
    :class:`ConfidenceLevel` — never computed by an LLM (ADR-0008 applies to
    this exactly as much as CVSS/risk scoring)."""
    if value >= 0.95:
        return ConfidenceLevel.CERTAIN
    if value >= LLM_FALLBACK_CONFIDENCE_CEILING:
        return ConfidenceLevel.HIGH
    if value >= 0.4:
        return ConfidenceLevel.MEDIUM
    if value >= 0.15:
        return ConfidenceLevel.LOW
    return ConfidenceLevel.UNKNOWN


class ConfidenceScore(BaseModel):
    """A confidence value plus its classified level and an optional
    human-readable rationale, attached to every agent output field
    (constitution §4.3, "confidence: float (0.0-1.0)")."""

    model_config = ConfigDict(frozen=True)

    value: float = Field(ge=0.0, le=1.0)
    #: Always derived from `value` by `_derive_level_if_absent` below when
    #: not passed explicitly; the default here exists only so callers like
    #: `deterministic()`/`llm_fallback()` can omit it and still type-check
    #: (mypy doesn't know the validator fills it in).
    level: ConfidenceLevel = ConfidenceLevel.UNKNOWN
    rationale: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _derive_level_if_absent(cls, data: object) -> object:
        if isinstance(data, dict) and "level" not in data and "value" in data:
            data = {**data, "level": classify_confidence(data["value"])}
        return data

    @classmethod
    def deterministic(cls, rationale: str | None = None) -> ConfidenceScore:
        """Confidence for a result backed entirely by a deterministic tool
        or parser — always 1.0 per constitution §4.6."""
        return cls(value=DETERMINISTIC_CONFIDENCE, rationale=rationale)

    @classmethod
    def llm_fallback(cls, value: float, rationale: str | None = None) -> ConfidenceScore:
        """Confidence for an LLM-derived inference, capped below the
        deterministic ceiling regardless of the requested value."""
        capped = min(value, LLM_FALLBACK_CONFIDENCE_CEILING)
        return cls(value=capped, rationale=rationale)
