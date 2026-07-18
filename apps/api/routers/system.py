"""System endpoints: ``/health``, ``/ready``, ``/version``.

Deliberately unversioned (mounted at the app root, not under ``/api/v1``) —
context/03_engineering_constitution.md §6 groups these as infrastructure
endpoints, not domain API surface subject to versioning.
"""

from __future__ import annotations

from fastapi import APIRouter

from apps.api.dependencies import DatabaseDep, SettingsDep
from core.exceptions import InfrastructureError
from core.schemas import (
    DependencyCheck,
    HealthResponse,
    ReadinessResponse,
    ServiceStatus,
    VersionResponse,
)

router = APIRouter(tags=["system"])


@router.get("/health", response_model=HealthResponse, summary="Liveness probe")
async def health() -> HealthResponse:
    """Is the process running and able to respond at all.

    Never checks external dependencies — that is the job of ``/ready``. A
    load balancer/orchestrator uses this to decide whether to restart the
    process, not whether to route traffic to it.
    """
    return HealthResponse()


@router.get("/ready", response_model=ReadinessResponse, summary="Readiness probe")
async def ready(database: DatabaseDep, settings: SettingsDep) -> ReadinessResponse:
    """Is the application able to serve real traffic — i.e. can it reach the
    dependencies a request will actually need.

    The database check is blocking (a DB outage means the app cannot serve
    any Case-related request). The LLM-provider-configured check is advisory
    only, matching the rest of the system's "never let an optional
    dependency block the whole app" posture (core/memory/README.md,
    docs/adr/0006-memory-strategy.md) — a missing LLM key degrades to
    "degraded," not "unavailable."
    """
    checks: list[DependencyCheck] = []

    try:
        await database.check_connection()
        checks.append(DependencyCheck(name="database", status=ServiceStatus.OK))
    except InfrastructureError as exc:
        checks.append(
            DependencyCheck(name="database", status=ServiceStatus.UNAVAILABLE, detail=exc.message)
        )

    if settings.llm_is_configured():
        checks.append(DependencyCheck(name="llm_provider", status=ServiceStatus.OK))
    else:
        checks.append(
            DependencyCheck(
                name="llm_provider",
                status=ServiceStatus.DEGRADED,
                detail=f"No credentials configured for provider '{settings.llm_provider}'.",
            )
        )

    if any(c.status is ServiceStatus.UNAVAILABLE for c in checks):
        overall = ServiceStatus.UNAVAILABLE
    elif any(c.status is ServiceStatus.DEGRADED for c in checks):
        overall = ServiceStatus.DEGRADED
    else:
        overall = ServiceStatus.OK

    return ReadinessResponse(status=overall, checks=checks)


@router.get("/version", response_model=VersionResponse, summary="Application version")
async def version(settings: SettingsDep) -> VersionResponse:
    """Application identity, for support/debugging."""
    return VersionResponse(
        name=settings.app_name,
        version=settings.app_version,
        environment=settings.app_env.value,
    )
