"""`ProviderRegistry` — plugin-capable registry for `ThreatIntelProvider`/
`IOCEnrichmentProvider` implementations, mirroring `core.threat_intel.
registry.ExtractorRegistry`'s shape. Starts empty: no concrete provider is
registered by this session's code (docs/adr/0012 point 4, explicit scope
cut) — this is the seam a future `MISPProvider` etc. plugs into.
"""

from __future__ import annotations

from functools import lru_cache
from importlib.metadata import entry_points

from pydantic import BaseModel, ConfigDict

from core.logging import get_logger
from core.threat_intel.exceptions import ThreatIntelError
from core.threat_intel.interfaces import IOCEnrichmentProvider, ThreatIntelProvider

_logger = get_logger(__name__)

#: Public extension contract — an out-of-tree package registers a
#: `ThreatIntelProvider`/`IOCEnrichmentProvider` implementation under this
#: `importlib.metadata` entry-point group to be auto-discovered.
PLUGIN_ENTRY_POINT_GROUP = "cdc.threat_intel_providers"

#: Well-known provider identifiers named by the task, used only as
#: `ProviderRegistration.name` conventions once a concrete provider is
#: registered — none of these constants have a corresponding implementation
#: yet.
MISP = "misp"
ALIENVAULT_OTX = "alienvault_otx"
VIRUSTOTAL = "virustotal"
ABUSEIPDB = "abuseipdb"
GREYNOISE = "greynoise"
OPENCTI = "opencti"


class ProviderNotFoundError(ThreatIntelError):
    """No registered provider matches the requested name."""

    code = "PROVIDER_NOT_FOUND"


class ProviderRegistration(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    provider: ThreatIntelProvider | IOCEnrichmentProvider
    name: str
    enabled: bool = True
    source: str = "plugin"


class ProviderRegistry:
    """Name-indexed registry for pluggable threat-intel providers. No
    builtin registrations — every entry arrives via `register()` or plugin
    discovery."""

    def __init__(self) -> None:
        self._registrations: dict[str, ProviderRegistration] = {}

    def register(
        self,
        provider: ThreatIntelProvider | IOCEnrichmentProvider,
        *,
        enabled: bool = True,
        source: str = "plugin",
    ) -> None:
        self._registrations[provider.provider_name] = ProviderRegistration(
            provider=provider, name=provider.provider_name, enabled=enabled, source=source
        )

    def get(self, name: str) -> ThreatIntelProvider | IOCEnrichmentProvider:
        registration = self._registrations.get(name)
        if registration is None or not registration.enabled:
            raise ProviderNotFoundError(f"No enabled provider registered as '{name}'.")
        return registration.provider

    def has(self, name: str) -> bool:
        return name in self._registrations

    def list_names(self) -> tuple[str, ...]:
        return tuple(self._registrations.keys())

    def load_plugins(self, *, group: str = PLUGIN_ENTRY_POINT_GROUP) -> int:
        """Same "fail gracefully, never abort discovery" contract as
        `core.threat_intel.registry.ExtractorRegistry.load_plugins` and
        `core.parsers.registry.ParserRegistry.load_plugins`."""
        loaded = 0
        for entry_point in entry_points(group=group):
            try:
                provider_cls = entry_point.load()
                instance = provider_cls()
                if not isinstance(instance, ThreatIntelProvider | IOCEnrichmentProvider):
                    raise TypeError(f"{entry_point.name} is not a recognized provider Protocol")
                self.register(instance, source="plugin")
                loaded += 1
            except Exception as exc:  # noqa: BLE001 - one bad plugin must not break discovery
                _logger.error(
                    "threat_intel_provider_plugin_load_failed",
                    plugin=entry_point.name,
                    error=str(exc),
                )
        return loaded


@lru_cache
def default_provider_registry() -> ProviderRegistry:
    """Process-wide cached, empty-by-default registry. Calling
    `.load_plugins()` here (rather than deferring to the caller) matches
    `default_parser_registry()`/`default_extractor_registry()`'s
    convention — plugin discovery is automatic, not opt-in."""
    registry = ProviderRegistry()
    registry.load_plugins()
    return registry
