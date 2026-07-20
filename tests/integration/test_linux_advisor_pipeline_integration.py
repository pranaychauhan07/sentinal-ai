"""Integration test for core/services/linux_advisor_service.py — exercises
the real `LinuxCommandInputParser` and the real `LinuxSecurityAdvisoryEngine`
together against `data/sample_evidence/linux_commands.txt` (a `chmod 777`
line, a `curl | bash` line, an `ls -l` listing showing `/etc/shadow` as
world-readable, and a benign `ls -la /home` line), proving detection
end-to-end (dangerous commands flagged, safe command explicitly marked safe,
hardening recommendations generated). Unlike the `core/vulnerabilities`/
`core/linux_security` integration tests, no database fixture is needed —
this framework never persists (ADR-0019).
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from core.config import get_settings
from core.linux_advisor.models import LinuxAdvisorSeverity
from core.parsers.base import RawEvidenceInput
from core.parsers.linux_command_parser import LinuxCommandInputParser
from core.services.linux_advisor_service import assess_linux_command_input

pytestmark = pytest.mark.integration

_LINUX_COMMANDS = Path("data/sample_evidence/linux_commands.txt")


def test_full_pipeline_from_real_evidence_fixture() -> None:
    parser = LinuxCommandInputParser()
    raw = RawEvidenceInput(filename="linux_commands.txt", content=_LINUX_COMMANDS.read_bytes())
    normalized_evidence = parser(raw)
    assert normalized_evidence.record_count == 4

    result = assess_linux_command_input(
        case_id=uuid.uuid4(), evidence=normalized_evidence, settings=get_settings()
    )
    advice = result.advice

    # Dangerous commands flagged.
    chmod_risk = next(c for c in advice.analyzed_commands if c.command.raw_text.startswith("chmod"))
    assert chmod_risk.severity == LinuxAdvisorSeverity.HIGH
    curl_risk = next(c for c in advice.analyzed_commands if c.command.raw_text.startswith("curl"))
    assert curl_risk.severity == LinuxAdvisorSeverity.CRITICAL

    # Safe command explicitly marked safe (a real, reachable outcome).
    safe_risk = next(c for c in advice.analyzed_commands if c.command.raw_text.startswith("ls -la"))
    assert safe_risk.severity == LinuxAdvisorSeverity.INFO
    assert safe_risk.matched_rule_ids == ()

    # ls -l entry showing /etc/shadow as world-readable flagged.
    assert len(advice.permission_analyses) == 1
    shadow_risk = advice.permission_analyses[0]
    assert shadow_risk.permission.filename == "/etc/shadow"
    assert shadow_risk.severity == LinuxAdvisorSeverity.CRITICAL

    # Hardening recommendations generated (both baseline and finding-triggered).
    assert advice.hardening_recommendations
    assert any(r.is_baseline for r in advice.hardening_recommendations)
    assert any(not r.is_baseline for r in advice.hardening_recommendations)

    assert advice.overall_risk_level == LinuxAdvisorSeverity.CRITICAL
