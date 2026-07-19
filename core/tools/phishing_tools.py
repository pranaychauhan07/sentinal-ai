"""`PhishingScoringTool` — the deterministic scoring math blueprint §7 calls
for the Phishing Investigation Agent ("Tools used: phishing_tools.py,
scoring.py"). Combines phishing-specific heuristics that have no existing
home (sender/reply-to domain mismatch, urgency/social-engineering keyword
density, attachment-extension risk) with the case's *already-extracted and
already-scored* URL/domain/email IOCs — this tool never re-extracts or
re-scores an IOC itself (constitution §1.9, "never reimplement... threat
scoring"); it only aggregates the composite scores it's handed.

Distinct from, and never duplicating, `core.tools.scoring.RiskScoringTool`
(scores raw log evidence severity distributions) — this tool scores email-
specific signals on its own independent 0-100 scale, matching blueprint §7's
"PhishingVerdict (score 0-100, indicators, recommended actions)".
"""

from __future__ import annotations

from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

from core.parsers.models import Severity
from core.tools.base import BaseTool

#: Deterministic bucket cut points for the phishing risk scale — mirrors
#: `core.tools.scoring.classify_risk_score`'s "hardcoded, stable scale"
#: pattern, kept as its own independent scale (constitution: this tool's
#: score is not the same measurement as `RiskScoringTool`'s).
_CRITICAL_THRESHOLD = 80.0
_HIGH_THRESHOLD = 55.0
_MEDIUM_THRESHOLD = 30.0
_LOW_THRESHOLD = 10.0

#: Case-insensitive urgency/social-engineering phrases — a documented,
#: reviewable heuristic (constitution §1.7: never a silent guess), not an
#: ML classifier. Deliberately phrase-level rather than single words to
#: reduce false positives on ordinary business email.
URGENCY_PHRASES: tuple[str, ...] = (
    "urgent",
    "immediately",
    "act now",
    "final notice",
    "verify your account",
    "verify your identity",
    "confirm your identity",
    "suspended",
    "permanently closed",
    "click here",
    "unauthorized access",
    "limited time",
    "failure to verify",
    "your account has been",
)

#: File extensions associated with executable/script payloads — a common,
#: conservative attachment-risk signal (blueprint §7: "attachment risk").
HIGH_RISK_ATTACHMENT_EXTENSIONS: frozenset[str] = frozenset(
    {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".jar", ".msi", ".ps1", ".com", ".pif"}
)


def classify_phishing_risk(value: float) -> Severity:
    """Pure, deterministic bucketing — never computed by an LLM
    (constitution §1.9)."""
    if value >= _CRITICAL_THRESHOLD:
        return Severity.CRITICAL
    if value >= _HIGH_THRESHOLD:
        return Severity.HIGH
    if value >= _MEDIUM_THRESHOLD:
        return Severity.MEDIUM
    if value >= _LOW_THRESHOLD:
        return Severity.LOW
    return Severity.INFO


def _domain_of(address: str) -> str:
    return address.rsplit("@", maxsplit=1)[-1].lower() if "@" in address else ""


def sender_reply_to_mismatch(from_address: str, reply_to_address: str) -> bool:
    """True only when both a sender and a distinct Reply-To domain are
    present and they differ — a classic phishing tell (replies routed
    somewhere other than the apparent sender). Absent Reply-To is not a
    mismatch (most legitimate email has none)."""
    if not from_address or not reply_to_address:
        return False
    return _domain_of(from_address) != _domain_of(reply_to_address)


def count_urgency_phrases(subject: str, body_text: str) -> int:
    """Case-insensitive count of `URGENCY_PHRASES` hits across subject+body,
    each phrase counted at most once (density, not raw occurrence count, is
    the deterministic signal — a single repeated phrase should not dominate
    the score)."""
    haystack = f"{subject}\n{body_text}".lower()
    return sum(1 for phrase in URGENCY_PHRASES if phrase in haystack)


def high_risk_attachments(attachments: list[dict[str, str]]) -> tuple[str, ...]:
    """Filenames whose extension is in `HIGH_RISK_ATTACHMENT_EXTENSIONS`."""
    flagged = []
    for attachment in attachments:
        filename = attachment.get("filename", "")
        if "." in filename:
            extension = "." + filename.rsplit(".", maxsplit=1)[-1].lower()
            if extension in HIGH_RISK_ATTACHMENT_EXTENSIONS:
                flagged.append(filename)
    return tuple(flagged)


class PhishingScoringWeights(BaseModel):
    """Configurable coefficients (constitution §2, "Constants... configurable
    weights"), independent linear contributions on a 0-100 scale, clamped at
    the tool boundary — matching `core.tools.scoring.ScoringWeights`'s shape."""

    model_config = ConfigDict(frozen=True)

    domain_mismatch: float = Field(default=25.0, ge=0.0)
    urgency_per_phrase: float = Field(default=8.0, ge=0.0)
    urgency_cap: float = Field(default=32.0, ge=0.0)
    attachment_risk: float = Field(default=20.0, ge=0.0)
    prompt_injection: float = Field(default=15.0, ge=0.0)
    #: Coefficient applied to the highest attributed IOC composite score
    #: (0-100) already computed by `core.threat_intel`'s Threat Scoring
    #: Engine — never recomputed here.
    ioc_scale: float = Field(default=0.3, ge=0.0, le=1.0)


class PhishingScoringInput(BaseModel):
    """One email's aggregate signal — every field here is already-extracted
    structure or an already-computed upstream score; this tool performs no
    parsing, extraction, or IOC scoring of its own."""

    model_config = ConfigDict(frozen=True)

    from_address: str = ""
    reply_to_address: str = ""
    subject: str = ""
    body_text: str = ""
    attachments: list[dict[str, str]] = Field(default_factory=list)
    #: Composite 0-100 scores for this evidence's already-scored URL/domain/
    #: email IOCs (`core.threat_intel.models.ScoredIOC.score.composite_score`).
    attributed_ioc_scores: list[float] = Field(default_factory=list)
    #: Whether `core.security.prompt_guard.scan_text` flagged the subject/
    #: body — a distinct signal from the IOC/heuristic scores above.
    prompt_injection_flagged: bool = False


class PhishingScoringOutput(BaseModel):
    model_config = ConfigDict(frozen=True)

    risk_score: float = Field(ge=0.0, le=100.0)
    risk_label: Severity
    sender_reply_to_mismatch: bool
    urgency_phrase_count: int
    high_risk_attachments: tuple[str, ...] = ()
    max_attributed_ioc_score: float = 0.0
    indicators: tuple[str, ...] = ()


class PhishingScoringTool(BaseTool[PhishingScoringInput, PhishingScoringOutput]):
    """Deterministic, no-I/O — never retried (constitution §5/§4.8). Given
    the same input, always returns the same output."""

    name: ClassVar[str] = "phishing_scoring"
    description: ClassVar[str] = (
        "Computes a 0-100 phishing risk score and indicator list from an "
        "email's sender/reply-to relationship, urgency-language density, "
        "attachment risk, and already-scored attributed IOCs."
    )
    is_io_bound: ClassVar[bool] = False

    def __init__(self, weights: PhishingScoringWeights | None = None) -> None:
        super().__init__()
        self._weights = weights or PhishingScoringWeights()

    def run(self, arguments: PhishingScoringInput) -> PhishingScoringOutput:
        weights = self._weights
        indicators: list[str] = []

        mismatch = sender_reply_to_mismatch(arguments.from_address, arguments.reply_to_address)
        if mismatch:
            indicators.append(
                f"Reply-To domain ('{_domain_of(arguments.reply_to_address)}') differs from "
                f"the From domain ('{_domain_of(arguments.from_address)}')."
            )

        urgency_count = count_urgency_phrases(arguments.subject, arguments.body_text)
        if urgency_count:
            indicators.append(
                f"{urgency_count} urgency/social-engineering phrase(s) detected in subject/body."
            )

        flagged_attachments = high_risk_attachments(arguments.attachments)
        if flagged_attachments:
            indicators.append(
                f"High-risk attachment extension(s): {', '.join(flagged_attachments)}."
            )

        max_ioc_score = max(arguments.attributed_ioc_scores, default=0.0)
        if max_ioc_score > 0:
            indicators.append(
                f"Embedded URL/domain/email indicator(s) scored up to "
                f"{max_ioc_score:.1f}/100 by the Threat Intelligence engine."
            )

        if arguments.prompt_injection_flagged:
            indicators.append(
                "Email content matched prompt-injection/jailbreak patterns "
                "(core.security.prompt_guard)."
            )

        score = 0.0
        score += weights.domain_mismatch if mismatch else 0.0
        score += min(weights.urgency_cap, urgency_count * weights.urgency_per_phrase)
        score += weights.attachment_risk if flagged_attachments else 0.0
        score += weights.prompt_injection if arguments.prompt_injection_flagged else 0.0
        score += max_ioc_score * weights.ioc_scale
        risk_score = max(0.0, min(100.0, score))

        return PhishingScoringOutput(
            risk_score=risk_score,
            risk_label=classify_phishing_risk(risk_score),
            sender_reply_to_mismatch=mismatch,
            urgency_phrase_count=urgency_count,
            high_risk_attachments=flagged_attachments,
            max_attributed_ioc_score=max_ioc_score,
            indicators=tuple(indicators),
        )
