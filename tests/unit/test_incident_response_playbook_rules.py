"""Unit tests for core/incident_response/playbook_rules.py."""

from __future__ import annotations

import pytest

from core.incident_response.inputs import IncidentInputFinding
from core.incident_response.models import IncidentSeverity, ResponseCategory
from core.incident_response.playbook_rules import build_action, match_categories

pytestmark = pytest.mark.unit


def test_credential_access_tactic_maps_to_password_and_account_categories() -> None:
    finding = IncidentInputFinding(
        finding_id="f1", severity=IncidentSeverity.HIGH, mitre_tactic_ids=("TA0006",)
    )
    categories = match_categories(finding)
    assert ResponseCategory.PASSWORD_RESET in categories
    assert ResponseCategory.ACCOUNT_DISABLEMENT in categories


def test_command_and_control_tactic_maps_to_network_containment() -> None:
    finding = IncidentInputFinding(
        finding_id="f1", severity=IncidentSeverity.CRITICAL, mitre_tactic_ids=("TA0011",)
    )
    categories = match_categories(finding)
    assert ResponseCategory.NETWORK_BLOCKING in categories
    assert ResponseCategory.IOC_BLOCKING in categories
    assert ResponseCategory.FIREWALL_UPDATE in categories


def test_unknown_tactic_id_falls_through_to_severity_fallback() -> None:
    finding = IncidentInputFinding(
        finding_id="f1", severity=IncidentSeverity.HIGH, mitre_tactic_ids=("TA9999",)
    )
    categories = match_categories(finding)
    assert categories == (ResponseCategory.EVIDENCE_PRESERVATION, ResponseCategory.HOST_ISOLATION)


def test_keyword_fallback_used_when_no_tactic_present() -> None:
    finding = IncidentInputFinding(
        finding_id="f1", severity=IncidentSeverity.MEDIUM, title="Brute force login attempt"
    )
    categories = match_categories(finding)
    assert ResponseCategory.ACCOUNT_DISABLEMENT in categories
    assert ResponseCategory.PASSWORD_RESET in categories


def test_vulnerability_keyword_maps_to_patch_prioritization() -> None:
    finding = IncidentInputFinding(
        finding_id="f1", severity=IncidentSeverity.HIGH, title="Exploitable CVE-2024-0001"
    )
    assert match_categories(finding) == (ResponseCategory.PATCH_PRIORITIZATION,)


def test_severity_only_fallback_when_no_tactic_or_keyword_matches() -> None:
    finding = IncidentInputFinding(
        finding_id="f1", severity=IncidentSeverity.MEDIUM, title="Unusual activity"
    )
    categories = match_categories(finding)
    assert categories == (ResponseCategory.EVIDENCE_PRESERVATION, ResponseCategory.EDR_ACTION)


def test_info_severity_with_no_match_yields_no_categories() -> None:
    finding = IncidentInputFinding(
        finding_id="f1", severity=IncidentSeverity.INFO, title="Routine login"
    )
    assert match_categories(finding) == ()


def test_categories_are_deduplicated_preserving_first_seen_order() -> None:
    # TA0003 (Persistence) matches HOST_ISOLATION and ACCOUNT_DISABLEMENT;
    # the "brute force" keyword would re-add ACCOUNT_DISABLEMENT — it must
    # not appear twice.
    finding = IncidentInputFinding(
        finding_id="f1",
        severity=IncidentSeverity.HIGH,
        mitre_tactic_ids=("TA0003",),
        title="brute force persistence",
    )
    categories = match_categories(finding)
    assert categories.count(ResponseCategory.ACCOUNT_DISABLEMENT) == 1


def test_build_action_substitutes_target_into_title_and_description() -> None:
    finding = IncidentInputFinding(
        finding_id="f1", severity=IncidentSeverity.HIGH, target="host-42"
    )
    action = build_action(finding, ResponseCategory.HOST_ISOLATION)
    assert "host-42" in action.title
    assert "host-42" in action.description
    assert action.target == "host-42"


def test_build_action_without_target_leaves_template_unmodified() -> None:
    finding = IncidentInputFinding(finding_id="f1", severity=IncidentSeverity.HIGH)
    action = build_action(finding, ResponseCategory.HOST_ISOLATION)
    assert action.title == "Isolate the affected host"
    assert action.target == ""
