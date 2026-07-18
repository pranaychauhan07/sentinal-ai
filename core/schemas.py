"""Shared, domain-agnostic Pydantic base models.

Only truly cross-cutting contracts live here (API error envelope, pagination,
health/readiness/version payloads) — per
context/03_engineering_constitution.md §3, domain models (``Finding``,
``NormalizedEvidence``, etc.) belong in the layer that defines them
(``core/agents``, ``core/parsers``), not in this module, once they exist.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class BaseSchema(BaseModel):
    """Common Pydantic configuration every shared/domain schema inherits.

    ``from_attributes`` lets these models be constructed directly from
    SQLAlchemy ORM instances in ``core/db`` repository code, matching
    context/03_engineering_constitution.md §7's ORM-to-Pydantic translation
    rule (translation happens in one place, using one consistent config).
    """

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class ErrorDetail(BaseSchema):
    """A single structured error payload, matching ``AppError.to_dict()``
    in core/exceptions.py."""

    code: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)


class ErrorResponse(BaseSchema):
    """Standardized API error envelope — every non-2xx response from
    apps/api uses this shape exclusively (context/03_engineering_constitution.md §6)."""

    error: ErrorDetail
    request_id: str | None = None


class PaginatedResponse(BaseSchema, Generic[T]):
    """Cursor-based pagination envelope for any list endpoint
    (context/03_engineering_constitution.md §6 — pagination from day one)."""

    items: list[T]
    next_cursor: str | None = None
    limit: int


class ServiceStatus(StrEnum):
    """Status reported by a single dependency check in the readiness probe."""

    OK = "ok"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


class HealthResponse(BaseSchema):
    """``GET /health`` — liveness only: is the process running and able to
    respond at all. Never checks external dependencies (that's ``/ready``)."""

    status: ServiceStatus = ServiceStatus.OK
    timestamp: datetime = Field(default_factory=lambda: datetime.now())


class DependencyCheck(BaseSchema):
    """One dependency's readiness result (database, LLM provider config, ...)."""

    name: str
    status: ServiceStatus
    detail: str | None = None


class ReadinessResponse(BaseSchema):
    """``GET /ready`` — is the application able to serve real traffic, i.e.
    can it reach its required dependencies. Individual dependency failures
    are advisory-vs-blocking per context/01_blueprint.md (e.g. the vector
    store is never blocking — see core/memory/README.md)."""

    status: ServiceStatus
    checks: list[DependencyCheck]
    timestamp: datetime = Field(default_factory=lambda: datetime.now())


class VersionResponse(BaseSchema):
    """``GET /version`` — application identity, for support/debugging."""

    name: str
    version: str
    environment: str
