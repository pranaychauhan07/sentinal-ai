"""Unit tests for core/parsers/ssh_auth_parser.py."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.parsers.base import RawEvidenceInput
from core.parsers.ssh_auth_parser import SshAuthParser

FIXTURE = Path("data/sample_evidence/ssh_auth.log")


@pytest.mark.unit
def test_parses_real_fixture_with_full_confidence() -> None:
    parser = SshAuthParser()
    raw = RawEvidenceInput(filename="ssh_auth.log", content=FIXTURE.read_bytes())
    result = parser(raw)
    assert result.confidence == 1.0
    assert result.unparsed_fragments == []
    assert result.record_count == 20


@pytest.mark.unit
def test_classifies_failed_and_accepted_logins() -> None:
    parser = SshAuthParser()
    raw = RawEvidenceInput(filename="ssh_auth.log", content=FIXTURE.read_bytes())
    result = parser(raw)
    event_types = {r.event_type for r in result.records}
    assert "auth_failure" in event_types
    assert "auth_success" in event_types

    failure = next(r for r in result.records if r.event_type == "auth_failure")
    assert failure.user == "admin"
    assert failure.ip_address == "203.0.113.44"

    success = next(r for r in result.records if r.event_type == "auth_success" and r.user == "root")
    assert success.ip_address == "203.0.113.44"


@pytest.mark.unit
def test_sniff_prefers_ssh_auth_over_generic_syslog() -> None:
    parser = SshAuthParser()
    line = "Jul 18 02:14:01 host sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2"
    raw = RawEvidenceInput(filename="auth.log", content=line.encode())
    assert parser.sniff(raw, line) > 0.5


@pytest.mark.unit
def test_non_sshd_lines_go_to_unparsed_fragments() -> None:
    parser = SshAuthParser()
    content = b"Jul 18 02:14:01 host cron[1]: (root) CMD (some job)\n"
    raw = RawEvidenceInput(filename="mixed.log", content=content)
    result = parser(raw)
    assert result.records == []
    assert len(result.unparsed_fragments) == 1


@pytest.mark.unit
def test_empty_content_degrades_gracefully() -> None:
    parser = SshAuthParser()
    raw = RawEvidenceInput(filename="empty.log", content=b"   ")
    result = parser(raw)
    assert result.confidence == 0.0
