"""``CommandAnalyzer`` — parses one raw command line and produces a
`CommandRisk`. Never executes, `eval`s, or shells out to the analyzed text
(constitution §10) — `shlex.split` is used purely to tokenize for display/
purpose-lookup purposes, with `ValueError` (malformed quoting) caught rather
than crashing (constitution §1.7).
"""

from __future__ import annotations

import shlex

from core.linux_advisor.command_rules import DEFAULT_COMMAND_RULES
from core.linux_advisor.models import CommandRisk, LinuxAdvisorSeverity, LinuxCommand, severity_rank
from core.linux_advisor.rule_engine import RuleEngine

#: Deterministic command -> plain-language purpose table (task brief: "at
#: minimum" this set of commands).
COMMAND_PURPOSES: dict[str, str] = {
    "chmod": "Changes the read/write/execute permission bits of a file or directory.",
    "chown": "Changes the owning user (and optionally group) of a file or directory.",
    "chgrp": "Changes the owning group of a file or directory.",
    "sudo": "Runs the given command with elevated (root, by default) privileges.",
    "curl": "Transfers data from or to a server (commonly used to download files/scripts).",
    "wget": "Downloads files from a URL non-interactively.",
    "rm": "Removes (deletes) files or directories.",
    "umask": "Sets the default permission mask applied to newly-created files/directories.",
    "useradd": "Creates a new user account.",
    "usermod": "Modifies an existing user account (including group memberships).",
    "passwd": "Changes a user's password (or, with options, account lock/expiry state).",
    "systemctl": "Controls systemd services (start/stop/enable/disable/status).",
    "ssh": "Opens a secure shell connection to a remote host.",
    "scp": "Securely copies files to/from a remote host over SSH.",
}

#: System paths whose ownership/modification implies root-level privilege is
#: required even without an explicit `sudo` prefix.
_ROOT_OWNED_PATH_PREFIXES: tuple[str, ...] = ("/etc", "/root", "/boot", "/sys", "/proc")


def _extract_target_paths(args: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(arg for arg in args if arg.startswith("/"))


def _has_pipe_to_shell(raw_text: str) -> bool:
    return "|" in raw_text and any(
        shell in raw_text.split("|")[-1] for shell in ("bash", "sh", "zsh")
    )


def _requires_privilege(
    command_name: str | None, has_sudo: bool, target_paths: tuple[str, ...]
) -> bool:
    if has_sudo:
        return True
    if command_name in {"useradd", "usermod", "passwd", "systemctl"}:
        return True
    return any(path.startswith(_ROOT_OWNED_PATH_PREFIXES) for path in target_paths)


def parse_command(raw_text: str) -> LinuxCommand:
    """Tokenizes `raw_text` via `shlex.split`, catching `ValueError`
    (unbalanced quotes) rather than raising — a command that fails to
    tokenize is still represented, with `tokenization_failed=True` and no
    parsed args, so the caller can still run rule-based text analysis
    against the raw string (constitution §1.7)."""
    try:
        tokens = shlex.split(raw_text, posix=True)
        tokenization_failed = False
    except ValueError:
        tokens = []
        tokenization_failed = True

    command_name = tokens[0] if tokens else None
    args = tuple(tokens[1:]) if tokens else ()
    has_sudo = command_name == "sudo"
    if has_sudo and args:
        command_name = args[0]
        args = args[1:]

    return LinuxCommand(
        raw_text=raw_text,
        command_name=command_name,
        args=args,
        has_sudo=has_sudo,
        has_pipe_to_shell=_has_pipe_to_shell(raw_text),
        target_paths=_extract_target_paths(args),
        tokenization_failed=tokenization_failed,
    )


class CommandAnalyzer:
    """Runs the default command `RuleEngine` against one raw command line
    and produces a `CommandRisk`. `severity=INFO` with no matched rules is a
    real, explicit "safe command" outcome, not merely an absence of
    findings."""

    def __init__(self, *, rule_engine: RuleEngine | None = None) -> None:
        self._rule_engine = rule_engine or RuleEngine(DEFAULT_COMMAND_RULES)

    def analyze(self, raw_text: str) -> CommandRisk:
        command = parse_command(raw_text)
        matches = self._rule_engine.evaluate(raw_text)

        purpose = COMMAND_PURPOSES.get(command.command_name or "")
        requires_privilege = _requires_privilege(
            command.command_name, command.has_sudo, command.target_paths
        )

        if not matches:
            return CommandRisk(
                command=command,
                severity=LinuxAdvisorSeverity.INFO,
                confidence=1.0,
                explanation=(
                    f"No known dangerous pattern matched for this command"
                    f"{f' ({command.command_name})' if command.command_name else ''}; "
                    "treated as a safe/benign command."
                ),
                purpose=purpose,
                requires_privilege=requires_privilege,
                matched_rule_ids=(),
            )

        # Highest-severity, highest-priority match drives the verdict;
        # every matched rule's explanation is still surfaced via
        # matched_rule_ids for a caller wanting full detail.
        top_match = max(matches, key=lambda m: (severity_rank(m.severity), m.confidence))
        return CommandRisk(
            command=command,
            severity=top_match.severity,
            confidence=top_match.confidence,
            explanation=top_match.explanation,
            recommended_action=top_match.safer_alternative,
            purpose=purpose,
            requires_privilege=requires_privilege,
            matched_rule_ids=tuple(m.rule_id for m in matches),
        )
