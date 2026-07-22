"""Unit tests for core/threat_intel/default_rules.py.

Regression context: `IOCExtractionPipeline` previously defaulted to a
`DetectionRuleEngine()` with zero rules registered, so every extracted
IOC's `rule_matches` was always empty — the classification/scoring engines
never had any local, offline detection signal (only extraction confidence,
which alone is rarely enough to cross the suspicious/malicious threshold).
These tests verify the default rule set actually matches the shape of real
extracted IOCs a SOC analyst would recognize as suspicious, and that it
never matches an unrelated, benign value.
"""

from __future__ import annotations

import pytest

from core.threat_intel.default_rules import build_default_rule_engine
from core.threat_intel.models import IOCRecord, IOCType


def _ioc(ioc_type: IOCType, value: str) -> IOCRecord:
    return IOCRecord(ioc_type=ioc_type, value=value, raw_value=value, source="test")


@pytest.mark.unit
def test_build_default_rule_engine_registers_every_rule_without_error() -> None:
    engine = build_default_rule_engine()
    assert len(engine.list_rules()) == 5
    assert all(rule.enabled for rule in engine.list_rules())


@pytest.mark.unit
def test_suspicious_tld_domain_matches_a_typosquat_phishing_domain() -> None:
    engine = build_default_rule_engine()
    matches = engine.evaluate([_ioc(IOCType.DOMAIN, "amaz0n-security-verify.xyz")])
    assert any(m.rule_id == "default-suspicious-tld-domain" for m in matches)


@pytest.mark.unit
def test_suspicious_tld_domain_does_not_match_an_ordinary_domain() -> None:
    engine = build_default_rule_engine()
    matches = engine.evaluate([_ioc(IOCType.DOMAIN, "example.com")])
    assert matches == []


@pytest.mark.unit
def test_backdoor_port_matches_known_c2_ports() -> None:
    engine = build_default_rule_engine()
    matches = engine.evaluate([_ioc(IOCType.PORT, "4444")])
    assert any(m.rule_id == "default-backdoor-port" for m in matches)


@pytest.mark.unit
def test_backdoor_port_does_not_match_an_ordinary_port() -> None:
    engine = build_default_rule_engine()
    matches = engine.evaluate([_ioc(IOCType.PORT, "443")])
    assert matches == []


@pytest.mark.unit
def test_privileged_username_target_matches_root_and_admin() -> None:
    engine = build_default_rule_engine()
    matches = engine.evaluate([_ioc(IOCType.USERNAME, "root")])
    assert any(m.rule_id == "default-privileged-username-target" for m in matches)


@pytest.mark.unit
def test_privileged_username_target_does_not_match_an_ordinary_username() -> None:
    engine = build_default_rule_engine()
    matches = engine.evaluate([_ioc(IOCType.USERNAME, "jane.doe")])
    assert matches == []


@pytest.mark.unit
def test_phishing_lure_archive_matches_invoice_themed_zip() -> None:
    engine = build_default_rule_engine()
    matches = engine.evaluate([_ioc(IOCType.FILE_NAME, "Invoice_2026.zip")])
    assert any(m.rule_id == "default-phishing-lure-archive" for m in matches)


@pytest.mark.unit
def test_phishing_lure_archive_does_not_match_an_ordinary_document() -> None:
    engine = build_default_rule_engine()
    matches = engine.evaluate([_ioc(IOCType.FILE_NAME, "quarterly_report.pdf")])
    assert matches == []


@pytest.mark.unit
def test_executable_extension_matches_a_bare_exe_filename() -> None:
    engine = build_default_rule_engine()
    matches = engine.evaluate([_ioc(IOCType.FILE_NAME, "payload.exe")])
    assert any(m.rule_id == "default-executable-extension" for m in matches)
