"""Unit tests for core/parsers/registry.py — the plugin-capable ParserRegistry."""

from __future__ import annotations

import pytest

from core.exceptions import NotFoundError
from core.parsers.base import BaseParser, RawEvidenceInput
from core.parsers.models import EvidenceType, NormalizedEvidence
from core.parsers.registry import ParserRegistry, default_parser_registry


class _FakeParser(BaseParser):
    name = "fake"
    description = "A fake parser for registry tests."
    evidence_type = EvidenceType.PLAIN_TEXT
    supported_extensions = (".fake",)

    def validate_content(self, raw: RawEvidenceInput, decoded_text: str) -> None:
        return None

    def parse_content(self, raw: RawEvidenceInput, decoded_text: str) -> NormalizedEvidence:
        return self._degraded_result(raw, decoded_text, reason="test parser")


@pytest.mark.unit
def test_register_and_get_by_name() -> None:
    registry = ParserRegistry()
    parser = _FakeParser()
    registry.register(parser)
    assert registry.get("fake") is parser


@pytest.mark.unit
def test_get_unknown_name_raises_not_found() -> None:
    registry = ParserRegistry()
    with pytest.raises(NotFoundError):
        registry.get("does_not_exist")


@pytest.mark.unit
def test_alias_resolves_to_registered_parser() -> None:
    registry = ParserRegistry()
    parser = _FakeParser()
    registry.register(parser, aliases=("fk",))
    assert registry.get("fk") is parser


@pytest.mark.unit
def test_disable_hides_parser_from_get_but_not_include_disabled() -> None:
    registry = ParserRegistry()
    parser = _FakeParser()
    registry.register(parser)
    registry.disable("fake")
    with pytest.raises(NotFoundError):
        registry.get("fake")
    assert registry.get("fake", include_disabled=True) is parser
    assert registry.has("fake") is False


@pytest.mark.unit
def test_find_by_evidence_type_orders_by_priority() -> None:
    registry = ParserRegistry()
    low = _FakeParser()

    class _OtherFakeParser(_FakeParser):
        name = "fake_high_priority"

    high = _OtherFakeParser()
    registry.register(low, priority=1)
    registry.register(high, priority=10)

    matches = registry.find_by_evidence_type(EvidenceType.PLAIN_TEXT)
    assert [m.parser.name for m in matches] == ["fake_high_priority", "fake"]


@pytest.mark.unit
def test_find_by_extension() -> None:
    registry = ParserRegistry()
    parser = _FakeParser()
    registry.register(parser)
    assert registry.find_by_extension(".fake")[0].parser is parser
    assert registry.find_by_extension(".unknown") == []


@pytest.mark.unit
def test_unregister_removes_parser_and_aliases() -> None:
    registry = ParserRegistry()
    parser = _FakeParser()
    registry.register(parser, aliases=("fk",))
    registry.unregister("fake")
    assert registry.has("fake") is False
    with pytest.raises(NotFoundError):
        registry.get("fk")


@pytest.mark.unit
def test_load_plugins_with_missing_group_is_a_noop() -> None:
    registry = ParserRegistry()
    assert registry.load_plugins(group="cdc.parsers.nonexistent.group") == 0


@pytest.mark.unit
def test_default_parser_registry_registers_all_ten_builtins() -> None:
    registry = default_parser_registry()
    assert registry.list_names() == (
        "apache_access",
        "apache_error",
        "csv_evidence",
        "email",
        "json_evidence",
        "nmap_xml",
        "plain_text",
        "ssh_auth",
        "syslog",
        "windows_event",
    )
