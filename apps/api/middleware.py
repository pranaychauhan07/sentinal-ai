"""Request lifecycle middleware: request-ID propagation, structured
request/response logging, and execution-time measurement.

One middleware, not two, because binding the request ID and measuring its
duration are the same lifecycle event
(context/03_engineering_constitution.md §1, "simplicity over cleverness") —
splitting them into separate middlewares would only duplicate the
start/finally bracketing for no benefit.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from core.logging import bind_request_id, clear_context, get_logger

logger = get_logger(__name__)

REQUEST_ID_HEADER = "X-Request-ID"


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Binds a request ID to the logging context for the lifetime of each
    request, logs a structured start/completion event with execution time,
    and echoes the request ID back on the response
    (context/03_engineering_constitution.md §8)."""

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        incoming_id = request.headers.get(REQUEST_ID_HEADER)
        request_id = bind_request_id(incoming_id)
        request.state.request_id = request_id
        start = time.perf_counter()

        logger.info("request_started", method=request.method, path=request.url.path)
        try:
            response = await call_next(request)
        except Exception:
            duration_ms = (time.perf_counter() - start) * 1000
            logger.error(
                "request_failed",
                method=request.method,
                path=request.url.path,
                duration_ms=round(duration_ms, 2),
            )
            raise
        else:
            duration_ms = (time.perf_counter() - start) * 1000
            logger.info(
                "request_completed",
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                duration_ms=round(duration_ms, 2),
            )
            response.headers[REQUEST_ID_HEADER] = request_id
            return response
        finally:
            clear_context()
