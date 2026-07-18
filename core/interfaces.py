"""Structural contracts (``typing.Protocol``) every concrete implementation
in this codebase must satisfy.

These are pure typing contracts with zero runtime dependencies on any other
``core/`` subpackage — a true leaf module, importable by every layer
(context/03_engineering_constitution.md §3, "common interfaces").
Concrete implementations live in their owning layer:

- ``Repository`` implementations → ``core/db/`` (once domain models exist)
- ``Agent`` implementations → ``core/agents/*.py``
- ``Tool`` implementations → ``core/tools/*.py``
- Services are plain modules/classes in ``core/services/`` and intentionally
  do **not** share one method signature (a ``case_service`` and a
  ``report_service`` do different things) — see the docstring on
  :class:`Service` below for the convention they follow instead of a shared
  Protocol method.
"""

from __future__ import annotations

from typing import Any, Protocol, TypeVar, runtime_checkable

ModelT = TypeVar("ModelT")
StateT = TypeVar("StateT")
#: Contravariant/covariant per standard Callable-protocol variance rules: a
#: Tool[InputT, OutputT] that accepts a wider input type or returns a
#: narrower output type is a valid substitute (Liskov substitution) — mypy
#: enforces this automatically once the variance is declared correctly.
InputT = TypeVar("InputT", contravariant=True)
OutputT = TypeVar("OutputT", covariant=True)


@runtime_checkable
class Repository(Protocol[ModelT]):
    """Contract every ``core/db`` repository implements for a given model.

    Deliberately minimal (CRUD + cursor-paginated list) — anything more
    specific (e.g. "find findings by severity") is an additional method on
    the concrete repository class, not forced into this shared Protocol.
    """

    async def get_by_id(self, entity_id: Any) -> ModelT | None: ...

    async def list(self, *, limit: int = 50, cursor: str | None = None) -> list[ModelT]: ...

    async def add(self, entity: ModelT) -> ModelT: ...

    async def delete(self, entity_id: Any) -> None: ...


@runtime_checkable
class Agent(Protocol[StateT]):
    """Contract every LangGraph agent node in ``core/agents/`` implements.

    Matches context/03_engineering_constitution.md §4.1 exactly: a single
    callable taking and returning the shared investigation state — no
    alternate entry points, no additional required methods. Parametrized
    over ``StateT`` rather than importing ``CaseInvestigationState`` directly
    so this module stays a dependency-free leaf; concrete agents will use
    ``Agent[CaseInvestigationState]``.
    """

    def __call__(self, state: StateT) -> StateT: ...


@runtime_checkable
class Tool(Protocol[InputT, OutputT]):
    """Contract every deterministic function in ``core/tools/`` implements
    when registered for LLM function-calling (context/03_engineering_constitution.md §5).

    ``name``/``description`` back the function-calling schema; ``__call__``
    is the deterministic computation itself.
    """

    name: str
    description: str

    def __call__(self, arguments: InputT) -> OutputT: ...


class Service:
    """Not a Protocol — a documented convention, not a structural contract.

    Concrete services (``core/services/case_service.py``,
    ``evidence_service.py``, ``report_service.py``) are plain modules
    exposing async functions, each with its own specific signature. They are
    "services" by folder placement and by following
    context/03_engineering_constitution.md §3's rule (thin orchestration
    over ``core/graph``, ``core/db``, ``core/reporting`` only) — not by
    implementing a shared method contract, which would force an artificial
    lowest-common-denominator API across genuinely different operations.
    This class exists only so the convention has a single documented,
    linkable location; it is never instantiated or subclassed.
    """

    def __init__(self) -> None:
        raise NotImplementedError(
            "core.interfaces.Service is documentation-only and must not be instantiated. "
            "Write a plain module with typed functions in core/services/ instead."
        )
