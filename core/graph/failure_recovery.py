"""Failure Recovery — what the workflow engine does when a node raises an
exception that escaped `BaseAgent`'s own handling (constitution §4.7's
per-agent fallback covers *documented* failure modes; this module covers
the *undocumented* ones per §9: "core/graph ... catch only truly unexpected
exceptions ... and convert them into a case-level ... state rather than
crashing").
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from core.exceptions import AgentExecutionError
from core.graph.state import CaseInvestigationState
from core.logging import get_logger

_logger = get_logger(__name__)


class RecoveryAction(StrEnum):
    """What happens to the workflow after an unrecoverable node exception."""

    CONTINUE_DEGRADED = "continue_degraded"  # log it, keep running the rest of the graph
    MANUAL_TRIAGE = "manual_triage"  # flag the case; graph still completes, not crashes
    ABORT_WORKFLOW = "abort_workflow"  # re-raise; only for exceptions in `abort_on`


class FailureRecoveryPolicy(BaseModel):
    """Immutable recovery configuration. Defaults to the most conservative
    documented behavior (route to manual triage) rather than silently
    continuing — constitution §10, "Safe defaults"."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    default_action: RecoveryAction = RecoveryAction.MANUAL_TRIAGE
    abort_on: tuple[type[Exception], ...] = ()


def recover(
    error: Exception,
    *,
    state: CaseInvestigationState,
    agent_name: str,
    policy: FailureRecoveryPolicy,
) -> CaseInvestigationState:
    """Convert an exception that escaped an agent node into a typed,
    recorded outcome on shared state, per `policy`. Never swallows the
    error silently (constitution §4.11, "Silently swallowing an exception
    with a bare except: pass" is a forbidden behavior) — it is always
    logged and recorded as an `ErrorRecord`, even when the workflow
    continues."""
    _logger.error("workflow_node_failed", agent_name=agent_name, error=str(error))
    state.add_error(agent_name, code=type(error).__name__, message=str(error))

    if isinstance(error, policy.abort_on):
        raise AgentExecutionError(
            f"Agent '{agent_name}' failed with an unrecoverable error: {error}",
            details={"agent": agent_name, "error_type": type(error).__name__},
        ) from error

    if policy.default_action is RecoveryAction.MANUAL_TRIAGE:
        state.requires_manual_triage = True
    elif policy.default_action is RecoveryAction.ABORT_WORKFLOW:
        raise AgentExecutionError(
            f"Agent '{agent_name}' failed and the recovery policy requires aborting: {error}",
            details={"agent": agent_name, "error_type": type(error).__name__},
        ) from error
    # RecoveryAction.CONTINUE_DEGRADED: the ErrorRecord above is the only
    # trace; the workflow proceeds as though this node produced no update.

    return state
