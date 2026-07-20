"""Integration test for core/services/linux_security_service.py — exercises
the real `SshAuthParser`/`SyslogParser`, the real `LinuxSecurityPipeline`,
and a real SQLite database together against
`data/sample_evidence/ssh_auth.log` (SSH brute force from one IP followed by
a successful login from that same IP) and
`data/sample_evidence/linux_security_syslog.log` (a sudo command touching
`/etc/shadow`, a new user creation immediately followed by a `usermod -aG
sudo`, and a suspicious cron entry piping curl output to bash) — proving
detection end-to-end through persistence, mirroring
tests/integration/test_vulnerability_pipeline_integration.py's pattern.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from core.config import Settings
from core.db import Base, Database
from core.parsers.base import RawEvidenceInput
from core.parsers.models import ChainOfCustody, EvidenceRecord, EvidenceType, NormalizedEvidence
from core.parsers.ssh_auth_parser import SshAuthParser
from core.parsers.syslog_parser import SyslogParser
from core.services.linux_security_service import (
    assess_linux_security,
    list_linux_security_findings_for_case,
)

pytestmark = pytest.mark.integration

_SSH_AUTH_LOG = Path("data/sample_evidence/ssh_auth.log")
_SYSLOG_LOG = Path("data/sample_evidence/linux_security_syslog.log")


@pytest.fixture
async def database(test_settings: Settings) -> AsyncIterator[Database]:
    db = Database(test_settings)
    async with db.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield db
    await db.dispose()


async def test_ssh_brute_force_and_compromise_detected_end_to_end(
    database: Database, test_settings: Settings
) -> None:
    parser = SshAuthParser()
    raw = RawEvidenceInput(filename="ssh_auth.log", content=_SSH_AUTH_LOG.read_bytes())
    normalized_evidence = parser(raw)
    assert normalized_evidence.confidence > 0.0

    case_id = uuid.uuid4()
    async with database.session_factory() as session:
        result = await assess_linux_security(
            session, case_id=case_id, evidence=normalized_evidence, settings=test_settings
        )
        await session.commit()

    categories = {
        c.candidate.category.value for c in result.normalized_linux_security_intel.candidates
    }
    assert "brute_force" in categories
    assert "compromise_after_brute_force" in categories
    assert "root_login" in categories

    brute_force_finding = next(
        f
        for f in result.normalized_linux_security_intel.findings
        if f.category.value == "brute_force"
    )
    assert brute_force_finding.subject == "203.0.113.44"

    async with database.session_factory() as session:
        persisted = await list_linux_security_findings_for_case(session, case_id)
        assert len(persisted) == result.finding_count
        assert all(p.case_id == case_id for p in persisted)


async def test_sudo_privesc_and_cron_chain_detected_end_to_end(
    database: Database, test_settings: Settings
) -> None:
    parser = SyslogParser()
    raw = RawEvidenceInput(filename="linux_security_syslog.log", content=_SYSLOG_LOG.read_bytes())
    normalized_evidence = parser(raw)
    assert normalized_evidence.record_count == 4

    case_id = uuid.uuid4()
    async with database.session_factory() as session:
        result = await assess_linux_security(
            session, case_id=case_id, evidence=normalized_evidence, settings=test_settings
        )
        await session.commit()

    categories = {
        c.candidate.category.value for c in result.normalized_linux_security_intel.candidates
    }
    # Sensitive-file sudo access.
    assert "sudo_abuse" in categories
    # New-user -> group-escalation combined pattern, re-flagged as persistence.
    assert "privilege_escalation" in categories
    assert "persistence_mechanism" in categories
    # Cron piping curl output to bash.
    assert "suspicious_cron" in categories


async def test_malformed_log_line_never_aborts_the_rest(
    database: Database, test_settings: Settings
) -> None:
    """A corrupted/unparseable record in the middle of an artifact must not
    prevent the well-formed records around it from being analyzed and
    persisted (constitution §1.7) — a regression test for the normalizer's
    per-record skip behavior."""
    records = [
        EvidenceRecord(
            line_number=1,
            timestamp=datetime.now(UTC),
            event_type="auth_success",
            user="root",
            ip_address="203.0.113.44",
        ),
        EvidenceRecord(line_number=2),  # corrupted: no usable signal at all
        EvidenceRecord(
            line_number=3,
            timestamp=datetime.now(UTC),
            event_type="auth_success",
            user="root",
            ip_address="198.51.100.9",
        ),
    ]
    evidence = NormalizedEvidence(
        evidence_type=EvidenceType.SSH_AUTH,
        source="synthetic_auth.log",
        parser_name="ssh_auth",
        parser_version="1.0.0",
        confidence=1.0,
        records=records,
        chain_of_custody=ChainOfCustody(
            ingested_at=datetime.now(UTC),
            ingested_by="tester",
            original_filename="synthetic_auth.log",
            sha256="a" * 64,
            file_size_bytes=10,
        ),
    )

    case_id = uuid.uuid4()
    async with database.session_factory() as session:
        result = await assess_linux_security(
            session, case_id=case_id, evidence=evidence, settings=test_settings
        )
        await session.commit()

    assert result.normalized_linux_security_intel.skipped_record_count == 1
    root_logins = [
        c
        for c in result.normalized_linux_security_intel.candidates
        if c.candidate.category.value == "root_login"
    ]
    assert len(root_logins) == 2  # both well-formed root logins still detected
