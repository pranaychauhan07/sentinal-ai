"""Unit tests for core/parsers/syslog_parser.py."""

from __future__ import annotations

import pytest

from core.parsers.base import RawEvidenceInput
from core.parsers.models import Severity
from core.parsers.syslog_parser import SyslogParser


@pytest.mark.unit
def test_parses_generic_syslog_line() -> None:
    parser = SyslogParser()
    content = b"Jul 18 02:14:01 web-prod-01 cron[1234]: (root) CMD (some job)\n"
    raw = RawEvidenceInput(filename="syslog.log", content=content)
    result = parser(raw)
    assert result.confidence == 1.0
    assert result.records[0].host == "web-prod-01"
    assert result.records[0].event_type == "cron"


@pytest.mark.unit
def test_infers_higher_severity_from_message_keywords() -> None:
    parser = SyslogParser()
    content = b"Jul 18 02:14:01 host kernel: ERROR: disk failure detected\n"
    raw = RawEvidenceInput(filename="syslog.log", content=content)
    result = parser(raw)
    assert result.records[0].severity == Severity.HIGH


@pytest.mark.unit
def test_unmatched_lines_are_unparsed_fragments() -> None:
    parser = SyslogParser()
    content = b"this is not a syslog line at all\n"
    raw = RawEvidenceInput(filename="syslog.log", content=content)
    result = parser(raw)
    assert result.confidence == 0.0
    assert result.unparsed_fragments == ["this is not a syslog line at all"]


@pytest.mark.unit
def test_empty_content_degrades() -> None:
    parser = SyslogParser()
    raw = RawEvidenceInput(filename="empty.log", content=b"")
    result = parser(raw)
    assert result.confidence == 0.0
