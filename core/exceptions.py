"""Shared exception hierarchy — context/03_engineering_constitution.md §9.

Every exception carries a machine-readable ``code``, a human-readable
``message``, and optional structured ``details``. `apps/api/exception_handlers.py`
maps these to the standardized error envelope in `core/schemas.py`; no other
translation to a user-facing message happens anywhere else in the codebase.
"""

from __future__ import annotations

from typing import Any


class AppError(Exception):
    """Base class for every exception raised deliberately by this
    application. Never raised directly — always via a subclass below."""

    #: Machine-readable error code (UPPER_SNAKE_CASE), stable across releases.
    code: str = "APP_ERROR"
    #: Default HTTP status code apps/api/exception_handlers.py maps this to.
    http_status: int = 500

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def to_dict(self) -> dict[str, Any]:
        """Serializable representation used to build the API error envelope."""
        return {"code": self.code, "message": self.message, "details": self.details}


class ValidationError(AppError):
    """Input failed validation at a system boundary (API request, evidence
    upload, tool arguments). Recoverable — the caller can correct and retry."""

    code = "VALIDATION_ERROR"
    http_status = 422


class NotFoundError(AppError):
    """A requested resource (Case, Evidence, Finding, Report) does not exist."""

    code = "NOT_FOUND"
    http_status = 404


class BusinessRuleError(AppError):
    """A domain/business rule was violated (e.g. attempting to close an
    already-closed case). Recoverable — distinct from ValidationError because
    the input was well-formed; it's the *action* that's not allowed."""

    code = "BUSINESS_RULE_VIOLATION"
    http_status = 409


class InfrastructureError(AppError):
    """A dependency the application owns/operates (database, filesystem)
    failed. Recoverable if the dependency was transient; fatal if it wasn't
    per context/03_engineering_constitution.md §9."""

    code = "INFRASTRUCTURE_ERROR"
    http_status = 503


class ExternalServiceError(AppError):
    """A third-party service the application depends on (LLM provider,
    future threat-intel feed) failed or returned an unexpected response."""

    code = "EXTERNAL_SERVICE_ERROR"
    http_status = 502


class AgentExecutionError(AppError):
    """An agent (core/agents/*) failed in a way with no documented,
    graceful fallback for the specific failure encountered — see
    docs/agent-design.md point 7. Distinct from a *handled* degraded result,
    which is not an exception at all but a low-confidence typed finding."""

    code = "AGENT_EXECUTION_ERROR"
    http_status = 500


class ToolExecutionError(AppError):
    """A deterministic tool (core/tools/*) failed to compute its result
    (e.g. malformed CVSS vector it could not parse). Caught by the calling
    agent and converted into a documented fallback — see
    context/03_engineering_constitution.md §4.7."""

    code = "TOOL_EXECUTION_ERROR"
    http_status = 500


class ApprovalRequiredError(AppError):
    """Raised when code attempts to mark an agent-recommended action as
    executed without first passing core/security/approval_gate.py. This is a
    programming-error guard, not a normal user-facing flow — see
    context/03_engineering_constitution.md §4.11 (forbidden behaviors)."""

    code = "APPROVAL_REQUIRED"
    http_status = 403
