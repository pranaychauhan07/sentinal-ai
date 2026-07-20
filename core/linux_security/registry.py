"""`LinuxSecurityProviderRegistry` — plugin-capable registry for
`LinuxSecurityEnrichmentProvider` implementations, mirroring
`core.vulnerabilities.registry.VulnerabilityProviderRegistry`'s shape. Starts
empty: no concrete provider is registered by this framework's code (an
explicit scope cut, mirroring ADR-0012/0017's identical cuts for their own
provider seams) — this is the seam a future provider plugs into.
"""

from __future__ import annotations

from functools import lru_cache
from importlib.metadata import entry_points

from pydantic import BaseModel, ConfigDict

from core.linux_security.exceptions import LinuxSecurityError
from core.linux_security.interfaces import LinuxSecurityEnrichmentProvider
from core.logging import get_logger

_logger = get_logger(__name__)

#: Public extension contract — an out-of-tree package registers a
#: `LinuxSecurityEnrichmentProvider` implementation under this
#: `importlib.metadata` entry-point group to be auto-discovered.
PLUGIN_ENTRY_POINT_GROUP = "cdc.linux_security_providers"


class ProviderNotFoundError(LinuxSecurityError):
    """No registered provider matches the requested name."""

    code = "LINUX_SECURITY_PROVIDER_NOT_FOUND"


class ProviderRegistration(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    provider: LinuxSecurityEnrichmentProvider
    name: str
    enabled: bool = True
    source: str = "plugin"


class LinuxSecurityProviderRegistry:
    """Name-indexed registry for pluggable Linux-security enrichment
    providers. No builtin registrations — every entry arrives via
    `register()` or plugin discovery."""

    def __init__(self) -> None:
        self._registrations: dict[str, ProviderRegistration] = {}

    def register(
        self,
        provider: LinuxSecurityEnrichmentProvider,
        *,
        enabled: bool = True,
        source: str = "plugin",
    ) -> None:
        self._registrations[provider.provider_name] = ProviderRegistration(
            provider=provider, name=provider.provider_name, enabled=enabled, source=source
        )

    def get(self, name: str) -> LinuxSecurityEnrichmentProvider:
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
        `core.vulnerabilities.registry.VulnerabilityProviderRegistry.load_plugins`."""
        loaded = 0
        for entry_point in entry_points(group=group):
            try:
                provider_cls = entry_point.load()
                instance = provider_cls()
                if not isinstance(instance, LinuxSecurityEnrichmentProvider):
                    raise TypeError(f"{entry_point.name} is not a recognized provider Protocol")
                self.register(instance, source="plugin")
                loaded += 1
            except Exception as exc:  # noqa: BLE001 - one bad plugin must not break discovery
                _logger.error(
                    "linux_security_provider_plugin_load_failed",
                    plugin=entry_point.name,
                    error=str(exc),
                )
        return loaded


@lru_cache
def default_linux_security_provider_registry() -> LinuxSecurityProviderRegistry:
    """Process-wide cached, empty-by-default registry. Calling
    `.load_plugins()` here matches `default_vulnerability_provider_registry()`'s
    convention — plugin discovery is automatic, not opt-in."""
    registry = LinuxSecurityProviderRegistry()
    registry.load_plugins()
    return registry
