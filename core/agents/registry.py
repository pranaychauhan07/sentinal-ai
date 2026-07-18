"""``AgentRegistry`` — where every concrete agent instance is registered so
the Coordinator/Planning agents (and, one layer up, `core/graph`) can look
one up by name instead of importing every specialist agent module directly.

This is what lets `core/graph/investigation_graph.py` add a new specialist
node by registering it here, without `core/agents/planning_agent.py` or
`core/graph/routing.py` changing at all — new agents extend the system by
registering a capability, not by editing framework code.
"""

from __future__ import annotations

from functools import lru_cache

from core.agents.base import BaseAgent
from core.agents.contracts import AgentIdentity
from core.exceptions import NotFoundError


class AgentRegistry:
    """An explicit, injectable registry (constitution §2, "Avoid global
    state") — construct one per process (see :func:`default_agent_registry`)
    or one per test for isolation from other tests' registrations."""

    def __init__(self) -> None:
        self._agents: dict[str, BaseAgent] = {}

    def register(self, agent: BaseAgent) -> None:
        self._agents[agent.name] = agent

    def get(self, name: str) -> BaseAgent:
        try:
            return self._agents[name]
        except KeyError as exc:
            raise NotFoundError(
                f"No agent registered under name '{name}'.",
                details={"agent": name, "available": sorted(self._agents)},
            ) from exc

    def has(self, name: str) -> bool:
        return name in self._agents

    def list_names(self) -> tuple[str, ...]:
        return tuple(sorted(self._agents))

    def list_identities(self) -> tuple[AgentIdentity, ...]:
        """What the Planning Agent matches capabilities against — identity
        only, never the agent instances themselves, so planning stays
        decoupled from execution."""
        return tuple(self._agents[name].identity for name in self.list_names())

    def find_by_capability(self, capability_name: str) -> tuple[AgentIdentity, ...]:
        return tuple(
            identity
            for identity in self.list_identities()
            if any(cap.name == capability_name for cap in identity.capabilities)
        )

    def unregister(self, name: str) -> None:
        self._agents.pop(name, None)


@lru_cache
def default_agent_registry() -> AgentRegistry:
    """Process-wide singleton, matching `core.tools.registry.default_tool_registry`
    and `core.config.get_settings`'s pattern. Concrete specialist agents
    register themselves here as they're implemented (Milestone M1+); only
    the Coordinator and Planning agents exist to register today."""
    return AgentRegistry()
