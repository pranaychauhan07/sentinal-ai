"""`MemoryRegistry` — a generic, named lookup table for pluggable memory
backend instances, mirroring `core.agents.registry.AgentRegistry` and
`core.tools.registry.ToolRegistry`'s pattern.

Unlike those two registries, memory backends don't share one common base
class (a `VectorMemory` and a `ConversationMemory` are structurally
unrelated Protocols) — so this registry is generic over whatever backend
type a given registry instance holds, rather than fixed to one type. A
future `MemoryManager` swap (e.g. registering a `ChromaVectorStore` under
the name `"vector_store"` once M6 lands, in place of `InMemoryVectorStore`)
is a registration change, not a code change anywhere that looks it up.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Generic, TypeVar

from core.exceptions import NotFoundError

BackendT = TypeVar("BackendT")


class MemoryRegistry(Generic[BackendT]):
    """An explicit, injectable registry (constitution §2, "avoid global
    state") for one category of memory backend. Construct one per backend
    category (e.g. `MemoryRegistry[VectorMemory]()`) rather than one giant
    registry mixing unrelated types."""

    def __init__(self) -> None:
        self._backends: dict[str, BackendT] = {}

    def register(self, name: str, backend: BackendT) -> None:
        self._backends[name] = backend

    def get(self, name: str) -> BackendT:
        try:
            return self._backends[name]
        except KeyError as exc:
            raise NotFoundError(
                f"No memory backend registered under name '{name}'.",
                details={"backend": name, "available": sorted(self._backends)},
            ) from exc

    def has(self, name: str) -> bool:
        return name in self._backends

    def list_names(self) -> tuple[str, ...]:
        return tuple(sorted(self._backends))

    def unregister(self, name: str) -> None:
        self._backends.pop(name, None)


@lru_cache
def default_memory_registry() -> MemoryRegistry[object]:
    """Process-wide singleton for ad hoc, loosely-typed backend lookup
    (e.g. a CLI/admin tool listing all registered memory backends by name).
    Type-specific call sites should prefer constructing/injecting their own
    `MemoryRegistry[SpecificBackendProtocol]` instead of narrowing this one,
    matching `default_agent_registry`/`default_tool_registry`'s documented
    singleton pattern."""
    return MemoryRegistry()
