"""`ExtractorRegistry` — plugin-capable registry for `BaseIOCExtractor`
implementations, mirroring `core.parsers.registry.ParserRegistry` exactly
(docs/adr/0012's "one data-driven engine ... extensibility ... provided by
ExtractorRegistry" refinement).
"""

from __future__ import annotations

from functools import lru_cache
from importlib.metadata import entry_points

from pydantic import BaseModel, ConfigDict

from core.logging import get_logger
from core.threat_intel.base import BaseIOCExtractor
from core.threat_intel.exceptions import ThreatIntelError
from core.threat_intel.models import IOCType

_logger = get_logger(__name__)

#: Public extension contract — an out-of-tree package registers a
#: `BaseIOCExtractor` subclass under this `importlib.metadata` entry-point
#: group to be auto-discovered by `default_extractor_registry()`.
PLUGIN_ENTRY_POINT_GROUP = "cdc.threat_intel_extractors"


class ExtractorNotFoundError(ThreatIntelError):
    """No registered extractor matches the requested name/alias."""

    code = "EXTRACTOR_NOT_FOUND"


class ExtractorRegistration(BaseModel):
    """One registered extractor plus its registry metadata."""

    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    extractor: BaseIOCExtractor
    name: str
    aliases: tuple[str, ...] = ()
    version: str
    priority: int = 0
    enabled: bool = True
    source: str = "builtin"


class ExtractorRegistry:
    """Name/alias/IOC-type indexed registry, identical shape to
    `ParserRegistry` (registration, enable/disable, priority tie-breaking,
    plugin discovery)."""

    def __init__(self) -> None:
        self._registrations: dict[str, ExtractorRegistration] = {}
        self._alias_index: dict[str, str] = {}

    def register(
        self,
        extractor: BaseIOCExtractor,
        *,
        aliases: tuple[str, ...] = (),
        priority: int = 0,
        enabled: bool = True,
        source: str = "builtin",
    ) -> None:
        registration = ExtractorRegistration(
            extractor=extractor,
            name=extractor.name,
            aliases=aliases,
            version=extractor.version,
            priority=priority,
            enabled=enabled,
            source=source,
        )
        self._registrations[extractor.name] = registration
        for alias in aliases:
            self._alias_index[alias] = extractor.name

    def _resolve_name(self, name_or_alias: str) -> str:
        return self._alias_index.get(name_or_alias, name_or_alias)

    def get(self, name_or_alias: str, *, include_disabled: bool = False) -> BaseIOCExtractor:
        resolved = self._resolve_name(name_or_alias)
        registration = self._registrations.get(resolved)
        if registration is None or (not include_disabled and not registration.enabled):
            raise ExtractorNotFoundError(
                f"No enabled extractor registered as '{name_or_alias}'.",
                details={"name": name_or_alias},
            )
        return registration.extractor

    def has(self, name_or_alias: str) -> bool:
        return self._resolve_name(name_or_alias) in self._registrations

    def enable(self, name: str) -> None:
        self._set_enabled(name, True)

    def disable(self, name: str) -> None:
        self._set_enabled(name, False)

    def _set_enabled(self, name: str, enabled: bool) -> None:
        resolved = self._resolve_name(name)
        registration = self._registrations.get(resolved)
        if registration is None:
            raise ExtractorNotFoundError(f"No extractor registered as '{name}'.")
        self._registrations[resolved] = registration.model_copy(update={"enabled": enabled})

    def unregister(self, name: str) -> None:
        resolved = self._resolve_name(name)
        self._registrations.pop(resolved, None)
        self._alias_index = {
            alias: target for alias, target in self._alias_index.items() if target != resolved
        }

    def list_names(self) -> tuple[str, ...]:
        return tuple(self._registrations.keys())

    def list_registrations(self) -> tuple[ExtractorRegistration, ...]:
        return tuple(self._registrations.values())

    def find_by_ioc_type(self, ioc_type: IOCType) -> list[ExtractorRegistration]:
        matches = [
            registration
            for registration in self._registrations.values()
            if registration.enabled and ioc_type in registration.extractor.ioc_types
        ]
        return sorted(matches, key=lambda registration: registration.priority, reverse=True)

    def load_plugins(self, *, group: str = PLUGIN_ENTRY_POINT_GROUP) -> int:
        """Discover and register third-party extractors. A missing group is
        a no-op; one failing plugin is logged and skipped, never aborting
        discovery of the rest (constitution §9, "fail gracefully")."""
        loaded = 0
        for entry_point in entry_points(group=group):
            try:
                extractor_cls = entry_point.load()
                instance = extractor_cls()
                if not isinstance(instance, BaseIOCExtractor):
                    raise TypeError(f"{entry_point.name} is not a BaseIOCExtractor")
                self.register(instance, source="plugin")
                loaded += 1
            except Exception as exc:  # noqa: BLE001 - one bad plugin must not break discovery
                _logger.error(
                    "threat_intel_extractor_plugin_load_failed",
                    plugin=entry_point.name,
                    error=str(exc),
                )
        return loaded


def _register_builtin_extractors(registry: ExtractorRegistry) -> None:
    from core.threat_intel.extractor import IOCExtractionEngine

    registry.register(IOCExtractionEngine(), aliases=("default", "regex_engine"), priority=100)


@lru_cache
def default_extractor_registry() -> ExtractorRegistry:
    """Process-wide cached registry — same singleton pattern as
    `core.parsers.registry.default_parser_registry`."""
    registry = ExtractorRegistry()
    _register_builtin_extractors(registry)
    registry.load_plugins()
    return registry
