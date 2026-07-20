"""Unit tests for core/parsers/linux_command_parser.py, including registry
priority/sniff behavior."""

from __future__ import annotations

import pytest

from core.parsers.base import RawEvidenceInput
from core.parsers.linux_command_parser import LinuxCommandInputParser
from core.parsers.models import EvidenceType
from core.parsers.registry import default_parser_registry

pytestmark = pytest.mark.unit


def _raw(content: str) -> RawEvidenceInput:
    return RawEvidenceInput(filename="commands.txt", content=content.encode())


def test_sniff_recognizes_ls_permission_prefix() -> None:
    parser = LinuxCommandInputParser()
    confidence = parser.sniff(_raw("x"), "-rwxr-xr-x 1 root root 0 Jan 1 00:00 /bin/x")
    assert confidence > 0.1


def test_sniff_recognizes_shebang() -> None:
    parser = LinuxCommandInputParser()
    confidence = parser.sniff(_raw("x"), "#!/bin/bash\necho hi")
    assert confidence > 0.1


def test_sniff_recognizes_security_relevant_command() -> None:
    parser = LinuxCommandInputParser()
    confidence = parser.sniff(_raw("x"), "chmod 777 /var/www")
    assert confidence > 0.1


def test_sniff_gives_zero_for_unrelated_text() -> None:
    parser = LinuxCommandInputParser()
    assert parser.sniff(_raw("x"), "Dear diary, today was a good day.") == 0.0


def test_parse_produces_one_record_per_nonblank_line() -> None:
    parser = LinuxCommandInputParser()
    raw = _raw("chmod 777 /var/www\n\nls -la /home\n")
    result = parser(raw)
    assert result.evidence_type == EvidenceType.LINUX_COMMAND_INPUT
    assert len(result.records) == 2
    assert result.records[0].raw_line == "chmod 777 /var/www"
    assert result.records[0].event_type == "linux_input_line"


def test_empty_input_degrades_not_crashes() -> None:
    parser = LinuxCommandInputParser()
    result = parser(_raw(""))
    assert result.confidence == 0.0
    assert result.records == []


def test_registry_priority_above_plain_text() -> None:
    registry = default_parser_registry()
    linux_registration = next(
        r for r in registry.list_registrations() if r.name == "linux_command_input"
    )
    plain_text_registration = next(
        r for r in registry.list_registrations() if r.name == "plain_text"
    )
    assert linux_registration.priority > plain_text_registration.priority


def test_registry_has_alias() -> None:
    registry = default_parser_registry()
    assert registry.get("linux_command") is registry.get("linux_command_input")
