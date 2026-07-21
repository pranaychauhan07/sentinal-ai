"""FastAPI application factory — the API Layer's entry point
(context/01_blueprint.md §4, docs/adr/0002-fastapi-service-boundary.md).

Run locally with:  uvicorn apps.api.main:app --reload --port 8000
(or ``make run-api``, see Makefile / docs/setup-guide.md).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi

from apps.api.exception_handlers import register_exception_handlers
from apps.api.middleware import RequestContextMiddleware
from apps.api.routers import system
from apps.api.routers.v1 import api_v1_router
from core.config import Settings, get_settings
from core.db import Database
from core.knowledge.bootstrap import register_default_knowledge_sources
from core.knowledge.registry import default_knowledge_registry
from core.logging import configure_logging, get_logger

logger = get_logger(__name__)

OPENAPI_TAGS: list[dict[str, str]] = [
    {"name": "system", "description": "Liveness, readiness, and version endpoints."},
    {"name": "cases", "description": "Case lifecycle and timeline."},
    {"name": "evidence", "description": "Evidence upload and the pipeline it triggers."},
    {"name": "iocs", "description": "Indicators of compromise extracted per case (read-only)."},
    {"name": "findings", "description": "MITRE-mapped Findings generated per case (read-only)."},
]


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application startup/shutdown. Constructs the one ``Database`` instance
    for the process lifetime and disposes its connection pool on shutdown —
    context/03_engineering_constitution.md §2 ("avoid global state": this is
    an explicit, documented singleton scoped to ``app.state``, not a module-
    level mutable global)."""
    settings = get_settings()
    configure_logging(settings)

    database = Database(settings)
    app.state.database = database
    app.state.settings = settings

    # Populates the process-wide `default_knowledge_registry()` singleton
    # (ADR-0027) once at startup — MITRE ATT&CK plus the three vendored
    # reference sources (OWASP Top 10, security/incident-response
    # playbooks, detection-engineering guidance). Never fatal: a missing/
    # malformed data file degrades that one source, logged, not application
    # startup (constitution §7).
    register_default_knowledge_sources(default_knowledge_registry(), settings)

    logger.info(
        "application_startup",
        environment=settings.app_env.value,
        version=settings.app_version,
    )
    try:
        yield
    finally:
        logger.info("application_shutdown")
        await database.dispose()


def _custom_openapi(app: FastAPI, settings: Settings) -> dict[str, Any]:
    """OpenAPI schema customization: project metadata, contact/license,
    cached after first generation per FastAPI's documented pattern."""

    def openapi() -> dict[str, Any]:
        if app.openapi_schema:
            return app.openapi_schema

        schema = get_openapi(
            title=settings.app_name,
            version=settings.app_version,
            description=(
                "AI-native, case-centric SOC analyst workbench. "
                "See context/01_blueprint.md and docs/architecture.md for the full design."
            ),
            routes=app.routes,
            tags=OPENAPI_TAGS,
        )
        schema["info"]["license"] = {"name": "MIT", "url": "https://opensource.org/licenses/MIT"}
        app.openapi_schema = schema
        return app.openapi_schema

    return openapi()  # type: ignore[func-returns-value]


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build and fully configure the FastAPI application.

    Accepting an optional ``settings`` override (rather than always calling
    ``get_settings()`` internally) is what makes this factory testable with
    isolated configuration — see tests/integration/test_api_system_endpoints.py.
    """
    resolved_settings = settings or get_settings()

    app = FastAPI(
        title=resolved_settings.app_name,
        version=resolved_settings.app_version,
        lifespan=_lifespan,
        openapi_tags=OPENAPI_TAGS,
    )

    app.add_middleware(RequestContextMiddleware)
    register_exception_handlers(app)

    app.include_router(system.router)
    app.include_router(api_v1_router)

    app.openapi = lambda: _custom_openapi(app, resolved_settings)  # type: ignore[method-assign]

    return app


app = create_app()
