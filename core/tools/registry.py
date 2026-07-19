"""``ToolRegistry`` — the lookup table agents use to find a tool by name
instead of importing concrete tool modules directly.

Per constitution §4.5, *which* tools an agent may call is declared
explicitly on the agent (`BaseAgent.tools_used`); this registry is what
resolves those declared names to actual callables at run time, and is the
seam a future MCP (Model Context Protocol) tool source would plug into
without changing any agent (see `core/tools/README.md`, "Future MCP
integration").
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from core.exceptions import NotFoundError
from core.tools.base import BaseTool


class ToolRegistry:
    """An explicit, injectable registry — never a module-level mutable dict
    (constitution §2, "Avoid global state"). Construct one per process (see
    :func:`default_tool_registry`) or one per test for isolation.

    Tools registered here have heterogeneous `InputT`/`OutputT` type
    parameters (a `CVSSTool` and a `MitreMappingTool` share no concrete
    input/output type), so entries are held as `BaseTool[Any, Any]` — the
    registry is a name-keyed lookup table, not a place that narrows a tool's
    contract; callers get the concrete type back by calling the tool.
    """

    def __init__(self) -> None:
        self._tools: dict[str, BaseTool[Any, Any]] = {}

    def register(self, tool: BaseTool[Any, Any]) -> None:
        """Register a tool instance under its declared `name`. Re-registering
        the same name overwrites the previous entry, which is a deliberate,
        explicit action (e.g. swapping a tool implementation in a test),
        never an accidental collision silently ignored."""
        self._tools[tool.name] = tool

    def get(self, name: str) -> BaseTool[Any, Any]:
        try:
            return self._tools[name]
        except KeyError as exc:
            raise NotFoundError(
                f"No tool registered under name '{name}'.",
                details={"tool": name, "available": sorted(self._tools)},
            ) from exc

    def has(self, name: str) -> bool:
        return name in self._tools

    def list_names(self) -> tuple[str, ...]:
        return tuple(sorted(self._tools))

    def unregister(self, name: str) -> None:
        self._tools.pop(name, None)


@lru_cache
def default_tool_registry() -> ToolRegistry:
    """Process-wide singleton, analogous to `core.config.get_settings` — an
    explicitly-designed, documented, cache-backed instance rather than
    ambient global mutable state (constitution §2's sanctioned exception).
    Concrete tool modules register themselves here as they're implemented
    (Milestone M1+); nothing does so yet."""
    return ToolRegistry()
