"""Unit tests for core/parsers/factory.py — deterministic parser selection."""

from __future__ import annotations

import pytest

from core.parsers.base import RawEvidenceInput
from core.parsers.exceptions import UnsupportedFormatError
from core.parsers.factory import select_parser
from core.parsers.models import EvidenceType
from core.parsers.registry import ParserRegistry
from core.parsers.ssh_auth_parser import SshAuthParser
from core.parsers.syslog_parser import SyslogParser


@pytest.fixture
def registry() -> ParserRegistry:
    reg = ParserRegistry()
    reg.register(SshAuthParser(), priority=10)
    reg.register(SyslogParser(), priority=5)
    return reg


@pytest.mark.unit
def test_select_parser_by_declared_type(registry: ParserRegistry) -> None:
    raw = RawEvidenceInput(
        filename="mystery.dat", content=b"anything", declared_type=EvidenceType.SYSLOG
    )
    parser = select_parser(registry, raw, "anything", extension=".dat")
    assert parser.name == "syslog"


@pytest.mark.unit
def test_select_parser_breaks_extension_tie_by_sniff_confidence(registry: ParserRegistry) -> None:
    ssh_line = "Jul 18 02:14:01 host sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2"
    raw = RawEvidenceInput(filename="auth.log", content=ssh_line.encode())
    parser = select_parser(registry, raw, ssh_line, extension=".log")
    assert parser.name == "ssh_auth"


@pytest.mark.unit
def test_select_parser_falls_back_to_content_sniff_when_no_extension_match(
    registry: ParserRegistry,
) -> None:
    ssh_line = "Jul 18 02:14:01 host sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2"
    raw = RawEvidenceInput(filename="evidence.dat", content=ssh_line.encode())
    parser = select_parser(registry, raw, ssh_line, extension=".dat")
    assert parser.name == "ssh_auth"


@pytest.mark.unit
def test_select_parser_raises_unsupported_format_when_nothing_matches(
    registry: ParserRegistry,
) -> None:
    raw = RawEvidenceInput(filename="weird.bin", content=b"\x00\x01\x02")
    with pytest.raises(UnsupportedFormatError):
        select_parser(registry, raw, "\x00\x01\x02", extension=".bin")
