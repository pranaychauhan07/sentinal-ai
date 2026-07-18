"""Maps every exception type this application raises to the standardized
``ErrorResponse`` envelope (core/schemas.py) —
context/03_engineering_constitution.md §6 ("Error responses") and §9
("Standardized API responses").

Registered once, in the app factory (apps/api/main.py). No router ever
constructs an error JSON body by hand.
"""

from __future__ import annotations

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from core.exceptions import AppError
from core.logging import get_logger
from core.schemas import ErrorDetail, ErrorResponse

logger = get_logger(__name__)


def _request_id(request: Request) -> str | None:
    """The request ID bound by RequestContextMiddleware for this request,
    falling back to a client-supplied header if the middleware didn't run
    (e.g. an error raised before it, which should not happen in practice
    since it's the outermost middleware)."""
    return getattr(request.state, "request_id", None) or request.headers.get("X-Request-ID")


def _envelope(
    code: str, message: str, details: dict[str, object], request: Request
) -> dict[str, object]:
    return ErrorResponse(
        error=ErrorDetail(code=code, message=message, details=details),
        request_id=_request_id(request),
    ).model_dump(mode="json")


async def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
    """Handles every deliberate application exception (core/exceptions.py)."""
    logger.warning("app_error", code=exc.code, message=exc.message, details=exc.details)
    return JSONResponse(
        status_code=exc.http_status,
        content=_envelope(exc.code, exc.message, exc.details, request),
    )


async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Handles FastAPI/Pydantic request-validation failures — a request that
    never reached business logic (context/03_engineering_constitution.md §9,
    "Validation errors")."""
    details = {"errors": exc.errors()}
    logger.warning("request_validation_error", details=details)
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=_envelope("VALIDATION_ERROR", "Request validation failed.", details, request),
    )


async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    """Handles routing-level HTTP errors (404 on an unknown path, 405, ...)
    so even these use the standardized envelope rather than FastAPI's default
    ``{"detail": ...}`` shape."""
    return JSONResponse(
        status_code=exc.status_code,
        content=_envelope("HTTP_ERROR", str(exc.detail), {}, request),
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Last-resort handler for anything not already a typed ``AppError``.

    Per context/03_engineering_constitution.md §9: the user-facing message
    is deliberately generic; full detail (exception type, stack trace) is
    only ever in the structured log, never in the response body.
    """
    logger.error("unhandled_exception", exception_type=type(exc).__name__, error=str(exc))
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=_envelope(
            "INTERNAL_SERVER_ERROR",
            "An unexpected error occurred. It has been logged for investigation.",
            {},
            request,
        ),
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Wire every handler above into the FastAPI app. Called once from the
    app factory."""
    app.add_exception_handler(AppError, app_error_handler)
    app.add_exception_handler(RequestValidationError, validation_error_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)
