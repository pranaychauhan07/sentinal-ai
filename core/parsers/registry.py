"""``ParserRegistry`` — the lookup table `core.parsers.factory.select_parser`
and `core/services/evidence_service.py` use to find a parser, instead of
importing concrete parser modules directly.

Plugin-capable by design (`docs/adr/0011-evidence-ingestion-pipeline-shape.md`
point 2): every registration carries an alias set, a version, a priority
(tie-break ordering when multiple parsers plausibly match the same input),
and an enable/disable flag (soft-disable without unregistering — useful for
a parser under investigation after a bug report). `load_plugins()` is a real,
working extension seam: a future out-of-tree parser package registers itself
via a `cdc.parsers` entry point with zero changes to this module.
"""

from __future__ import annotations

from functools import lru_cache
from importlib.metadata import entry_points

from pydantic import BaseModel, ConfigDict

from core.exceptions import NotFoundError
from core.logging import get_logger
from core.parsers.base import BaseParser
from core.parsers.models import EvidenceType

_logger = get_logger(__name__)

#: The `importlib.metadata` entry-point group external parser plugins
#: register under, e.g. in a plugin package's `pyproject.toml`:
#: `[project.entry-points."cdc.parsers"]\nmy_parser = "my_pkg.parser:MyParser"`
PLUGIN_ENTRY_POINT_GROUP = "cdc.parsers"


class ParserRegistration(BaseModel):
    """One registered parser plus the registry-level metadata governing how
    it's discovered — kept separate from `BaseParser` itself so a parser
    class never has to know its own priority/aliases/enabled-state."""

    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    parser: BaseParser
    name: str
    aliases: tuple[str, ...] = ()
    version: str
    priority: int = 0
    enabled: bool = True
    source: str = "builtin"


class ParserRegistry:
    """An explicit, injectable registry — never a module-level mutable dict
    (constitution §2, "avoid global state"). Construct one per process (see
    `default_parser_registry`) or one per test for isolation.
    """

    def __init__(self) -> None:
        self._registrations: dict[str, ParserRegistration] = {}
        self._alias_index: dict[str, str] = {}

    def register(
        self,
        parser: BaseParser,
        *,
        aliases: tuple[str, ...] = (),
        priority: int = 0,
        enabled: bool = True,
        source: str = "builtin",
    ) -> None:
        """Register `parser` under its declared `name`. Re-registering the
        same name overwrites the previous entry — a deliberate, explicit
        action (e.g. a plugin intentionally superseding a builtin), never an
        accidental silent collision."""
        registration = ParserRegistration(
            parser=parser,
            name=parser.name,
            aliases=aliases,
            version=parser.version,
            priority=priority,
            enabled=enabled,
            source=source,
        )
        self._registrations[parser.name] = registration
        for alias in aliases:
            self._alias_index[alias] = parser.name

    def _resolve_name(self, name_or_alias: str) -> str:
        return self._alias_index.get(name_or_alias, name_or_alias)

    def get(self, name_or_alias: str, *, include_disabled: bool = False) -> BaseParser:
        resolved = self._resolve_name(name_or_alias)
        registration = self._registrations.get(resolved)
        if registration is None or (not registration.enabled and not include_disabled):
            raise NotFoundError(
                f"No enabled parser registered under name/alias '{name_or_alias}'.",
                details={"requested": name_or_alias, "available": self.list_names()},
            )
        return registration.parser

    def has(self, name_or_alias: str) -> bool:
        resolved = self._resolve_name(name_or_alias)
        registration = self._registrations.get(resolved)
        return registration is not None and registration.enabled

    def enable(self, name: str) -> None:
        self._set_enabled(name, True)

    def disable(self, name: str) -> None:
        self._set_enabled(name, False)

    def _set_enabled(self, name: str, enabled: bool) -> None:
        registration = self._registrations.get(name)
        if registration is None:
            raise NotFoundError(f"No parser registered under name '{name}'.")
        self._registrations[name] = registration.model_copy(update={"enabled": enabled})

    def unregister(self, name: str) -> None:
        registration = self._registrations.pop(name, None)
        if registration is not None:
            for alias in registration.aliases:
                self._alias_index.pop(alias, None)

    def list_names(self) -> tuple[str, ...]:
        return tuple(sorted(self._registrations))

    def list_registrations(self) -> tuple[ParserRegistration, ...]:
        return tuple(self._registrations.values())

    def find_by_evidence_type(self, evidence_type: EvidenceType) -> list[ParserRegistration]:
        """Enabled registrations claiming `evidence_type`, highest priority
        first — ties broken by registration order (stable sort)."""
        matches = [
            reg
            for reg in self._registrations.values()
            if reg.enabled and reg.parser.evidence_type == evidence_type
        ]
        return sorted(matches, key=lambda reg: reg.priority, reverse=True)

    def find_by_extension(self, extension: str) -> list[ParserRegistration]:
        """Enabled registrations claiming `extension` (e.g. `.log`),
        highest priority first."""
        matches = [
            reg
            for reg in self._registrations.values()
            if reg.enabled and extension in reg.parser.supported_extensions
        ]
        return sorted(matches, key=lambda reg: reg.priority, reverse=True)

    def load_plugins(self, *, group: str = PLUGIN_ENTRY_POINT_GROUP) -> int:
        """Discover and register external parser plugins via
        `importlib.metadata` entry points. A missing/empty group is a
        documented no-op (no plugin package needs to exist for this
        codebase to work); a single failing plugin is logged and skipped,
        never aborts discovery of the rest (constitution §9, "fail
        gracefully"). Returns the number of plugins successfully registered.
        """
        loaded = 0
        try:
            discovered = entry_points(group=group)
        except Exception as exc:  # noqa: BLE001 - entry-point discovery must never crash startup
            _logger.warning("parser_plugin_discovery_failed", group=group, error=str(exc))
            return 0

        for entry_point in discovered:
            try:
                parser_cls = entry_point.load()
                parser_instance = parser_cls()
                if not isinstance(parser_instance, BaseParser):
                    raise TypeError(f"Plugin '{entry_point.name}' does not implement BaseParser.")
                self.register(parser_instance, source="plugin")
                loaded += 1
            except Exception as exc:  # noqa: BLE001 - one bad plugin must not block the rest
                _logger.error("parser_plugin_load_failed", plugin=entry_point.name, error=str(exc))
        return loaded


@lru_cache
def default_parser_registry() -> ParserRegistry:
    """Process-wide singleton, analogous to `core.tools.registry.
    default_tool_registry` — an explicitly-designed, documented, cache-backed
    instance rather than ambient global mutable state (constitution §2's
    sanctioned exception). Auto-registers every builtin parser, then
    attempts plugin discovery (a safe no-op if none are installed).
    """
    registry = ParserRegistry()
    _register_builtin_parsers(registry)
    registry.load_plugins()
    return registry


def _register_builtin_parsers(registry: ParserRegistry) -> None:
    from core.parsers.apache_access_parser import ApacheAccessParser
    from core.parsers.apache_error_parser import ApacheErrorParser
    from core.parsers.csv_evidence_parser import CsvEvidenceParser
    from core.parsers.email_parser import EmailParser
    from core.parsers.http_transaction_parser import HttpTransactionParser
    from core.parsers.json_evidence_parser import JsonEvidenceParser
    from core.parsers.linux_command_parser import LinuxCommandInputParser
    from core.parsers.nessus_csv_parser import NessusCsvParser
    from core.parsers.nessus_parser import NessusXmlParser
    from core.parsers.nmap_parser import NmapXmlParser
    from core.parsers.openvas_csv_parser import OpenVasCsvParser
    from core.parsers.openvas_parser import OpenVasXmlParser
    from core.parsers.plaintext_parser import PlainTextParser
    from core.parsers.ssh_auth_parser import SshAuthParser
    from core.parsers.syslog_parser import SyslogParser
    from core.parsers.windows_event_parser import WindowsEventParser

    # Priority > 0 for parsers with a more specific `sniff()` than the
    # generic syslog/plain-text fallbacks, so ties resolve toward specificity.
    registry.register(SshAuthParser(), aliases=("auth_log",), priority=10)
    registry.register(ApacheAccessParser(), aliases=("apache_combined",), priority=10)
    registry.register(ApacheErrorParser(), priority=10)
    registry.register(SyslogParser(), priority=5)
    registry.register(EmailParser(), aliases=("eml",), priority=10)
    registry.register(WindowsEventParser(), aliases=("evtx", "windows_security"), priority=10)
    registry.register(JsonEvidenceParser(), priority=5)
    registry.register(CsvEvidenceParser(), priority=1)
    registry.register(NmapXmlParser(), aliases=("nmap",), priority=10)
    registry.register(NessusXmlParser(), aliases=("nessus",), priority=10)
    registry.register(NessusCsvParser(), priority=8)
    registry.register(OpenVasXmlParser(), aliases=("openvas",), priority=9)
    registry.register(OpenVasCsvParser(), priority=7)
    registry.register(LinuxCommandInputParser(), aliases=("linux_command",), priority=3)
    registry.register(HttpTransactionParser(), aliases=("http",), priority=3)
    registry.register(PlainTextParser(), priority=0)
