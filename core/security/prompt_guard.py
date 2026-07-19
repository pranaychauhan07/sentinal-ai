"""Prompt Injection / Jailbreak Guard — the Security Layer's first concrete
implementation (`context/01_blueprint.md` §4/§10, constitution §4.11/§9/§10).

Screens any attacker-or-third-party-authored text (a phishing email's
subject/body, eventually uploaded source code) for prompt-injection/jailbreak
*shapes* before that text is ever interpolated into an LLM prompt. Applied
structurally — every agent that consumes untrusted text is required to call
this first (constitution §4.11: "Including unsanitized, unguarded
attacker-controlled text ... without first passing it through
`core/security/prompt_guard.py`" is a forbidden, blocking-review agent
behavior).

Deterministic, pattern-based detection only (constitution §1.9: judgment/
synthesis is the LLM's job; a fixed, checkable answer is a plain function's
job) — never itself an LLM call, since a guard that could itself be
manipulated by the text it's screening would defeat its own purpose.

Per `docs/dependency-rules.md` rule 8, this module has no outbound
dependency on any other `core/` subpackage except `core/config` (for
operator-supplied pattern overrides) — a guardrail must not be influenced by
the logic it guards.

Honest limitation, stated once here rather than implied: this is a
heuristic, signature-based defense layer, not a guarantee. A sufficiently
novel injection phrasing may not match any pattern below. It raises the cost
of a naive attack and gives the analyst a visible signal; it does not claim
to be exhaustive.
"""

from __future__ import annotations

import re
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from core.config import Settings

#: Injection/jailbreak *shapes* this guard recognizes, expressed as regex
#: fragments matched case-insensitively against the whole text. Grouped by
#: the tactic they represent (constitution §2, "Constants... defined once").
_INSTRUCTION_OVERRIDE_PATTERNS: tuple[str, ...] = (
    r"\bignore\b.{0,30}\binstructions\b",
    r"\bdisregard\b.{0,30}\binstructions\b",
    r"\bforget\b.{0,30}\binstructions\b",
    r"new instructions?:",
    r"do not follow.{0,30}\binstructions\b",
)
_ROLE_OVERRIDE_PATTERNS: tuple[str, ...] = (
    r"you are now",
    r"act as (if you are |a )?",
    r"pretend (to be|you are)",
    r"system prompt",
    r"you (are|'re) no longer",
    r"developer mode",
    r"jailbreak",
)
_EXFILTRATION_PATTERNS: tuple[str, ...] = (
    r"reveal your (system )?prompt",
    r"print your instructions",
    r"repeat (the words|everything) above",
    r"what (were|are) your (initial|original) instructions",
)
_OBFUSCATION_PATTERNS: tuple[str, ...] = (
    r"base64",
    r"rot13",
    r"decode the following",
)

_PATTERN_GROUPS: dict[str, tuple[str, ...]] = {
    "instruction_override": _INSTRUCTION_OVERRIDE_PATTERNS,
    "role_override": _ROLE_OVERRIDE_PATTERNS,
    "exfiltration": _EXFILTRATION_PATTERNS,
    "obfuscation": _OBFUSCATION_PATTERNS,
}


class PromptInjectionCategory(StrEnum):
    """Which tactic a matched pattern represents — surfaced so a caller/UI
    can explain *why* text was flagged, not just that it was."""

    INSTRUCTION_OVERRIDE = "instruction_override"
    ROLE_OVERRIDE = "role_override"
    EXFILTRATION = "exfiltration"
    OBFUSCATION = "obfuscation"


class PromptInjectionMatch(BaseModel):
    """One matched pattern — the evidence behind a guard verdict."""

    model_config = ConfigDict(frozen=True)

    category: PromptInjectionCategory
    pattern: str
    matched_text: str


class PromptGuardResult(BaseModel):
    """The guard's verdict on one piece of untrusted text. `is_flagged`
    is the single boolean a calling agent branches on; `matches` is the
    audit detail logged alongside it (constitution §8)."""

    model_config = ConfigDict(frozen=True)

    is_flagged: bool
    matches: tuple[PromptInjectionMatch, ...] = Field(default_factory=tuple)

    @property
    def match_count(self) -> int:
        return len(self.matches)


def _compiled_patterns(
    settings: Settings | None,
) -> dict[PromptInjectionCategory, list[re.Pattern[str]]]:
    compiled: dict[PromptInjectionCategory, list[re.Pattern[str]]] = {
        PromptInjectionCategory(name): [re.compile(p, re.IGNORECASE) for p in patterns]
        for name, patterns in _PATTERN_GROUPS.items()
    }
    extra_patterns = settings.prompt_guard_extra_pattern_list if settings else []
    if extra_patterns:
        compiled[PromptInjectionCategory.INSTRUCTION_OVERRIDE].extend(
            re.compile(p, re.IGNORECASE) for p in extra_patterns
        )
    return compiled


def scan_text(text: str, *, settings: Settings | None = None) -> PromptGuardResult:
    """Screen `text` for prompt-injection/jailbreak shapes. Pure and
    deterministic (constitution §1.9) — the same input always yields the
    same result. `settings` is optional and used only for
    `PROMPT_GUARD_EXTRA_PATTERNS` operator-supplied additions; omit it to run
    with the built-in pattern set only."""
    if not text:
        return PromptGuardResult(is_flagged=False)

    matches: list[PromptInjectionMatch] = []
    for category, patterns in _compiled_patterns(settings).items():
        for pattern in patterns:
            found = pattern.search(text)
            if found:
                matches.append(
                    PromptInjectionMatch(
                        category=category,
                        pattern=pattern.pattern,
                        matched_text=found.group(0),
                    )
                )

    return PromptGuardResult(is_flagged=bool(matches), matches=tuple(matches))
