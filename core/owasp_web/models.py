"""Domain models for `core/owasp_web` — a deterministic HTTP-traffic security
analyzer mapping findings to the OWASP Top 10 (2021) taxonomy.

Owns its own severity scale (`WebSecuritySeverity`) rather than reusing
`core.parsers.models.Severity` or any sibling leaf's — matching the
already-established "each leaf owns its own severity scale" precedent from
`docs/adr/0017-vulnerability-assessment-framework.md` point 2 /
`docs/adr/0018-linux-security-threat-hunting-framework.md` point 2 /
`docs/adr/0019-linux-security-advisor-agent.md` point 4.
"""

from __future__ import annotations

from enum import IntEnum, StrEnum

from pydantic import BaseModel, ConfigDict, Field


class OwaspCategory(StrEnum):
    """The ten OWASP Top 10 (2021) categories — this package's defining
    taxonomy. Used directly on every finding model and on
    `rule_engine.Rule.category` (stronger typing than a plain `str`, since
    OWASP-category mapping is this agent's core responsibility)."""

    A01_BROKEN_ACCESS_CONTROL = "a01_broken_access_control"
    A02_CRYPTOGRAPHIC_FAILURES = "a02_cryptographic_failures"
    A03_INJECTION = "a03_injection"
    A04_INSECURE_DESIGN = "a04_insecure_design"
    A05_SECURITY_MISCONFIGURATION = "a05_security_misconfiguration"
    A06_VULNERABLE_COMPONENTS = "a06_vulnerable_and_outdated_components"
    A07_AUTHENTICATION_FAILURES = "a07_identification_and_authentication_failures"
    A08_SOFTWARE_DATA_INTEGRITY_FAILURES = "a08_software_and_data_integrity_failures"
    A09_LOGGING_MONITORING_FAILURES = "a09_security_logging_and_monitoring_failures"
    A10_SSRF = "a10_server_side_request_forgery"


class WebSecuritySeverity(StrEnum):
    """This package's own severity scale — never shared with
    `core.linux_advisor.models.LinuxAdvisorSeverity` or any other sibling
    leaf's."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


#: Ordering for `max()`/comparison use, highest severity last.
_SEVERITY_ORDER: dict[WebSecuritySeverity, int] = {
    WebSecuritySeverity.INFO: 0,
    WebSecuritySeverity.LOW: 1,
    WebSecuritySeverity.MEDIUM: 2,
    WebSecuritySeverity.HIGH: 3,
    WebSecuritySeverity.CRITICAL: 4,
}


def severity_rank(severity: WebSecuritySeverity) -> int:
    """Deterministic ordinal for a `WebSecuritySeverity` — the one place this
    ranking is defined (constitution §2, "a magic number that appears in two
    places will eventually be updated in only one")."""
    return _SEVERITY_ORDER[severity]


def highest_severity(severities: list[WebSecuritySeverity]) -> WebSecuritySeverity:
    if not severities:
        return WebSecuritySeverity.INFO
    return max(severities, key=severity_rank)


class MatcherKind(StrEnum):
    """The tagged-union discriminator for `rule_engine.Rule.matcher`."""

    REGEX = "regex"
    LITERAL_SUBSTRING = "literal_substring"
    CALLABLE_SIGNATURE = "callable_signature"


class RulePriority(IntEnum):
    """Illustrative named priority bands — rules may use any int; these are
    convenience constants, not an exhaustive enum of legal values."""

    LOWEST = 0
    LOW = 25
    MEDIUM = 50
    HIGH = 75
    HIGHEST = 100


class RuleMatch(BaseModel):
    """One `rule_engine.RuleEngine` match against a piece of text."""

    model_config = ConfigDict(frozen=True)

    rule_id: str
    category: OwaspCategory
    severity: WebSecuritySeverity
    confidence: float = Field(ge=0.0, le=1.0)
    explanation: str
    recommendation: str | None = None
    matched_text: str = ""


class ParsedHeader(BaseModel):
    """One parsed `Name: Value` HTTP header line."""

    model_config = ConfigDict(frozen=True)

    raw_text: str
    name: str
    value: str


class ParsedCookie(BaseModel):
    """One parsed `Set-Cookie` line's attributes — `cookie_analyzer.py`'s
    intermediate representation."""

    model_config = ConfigDict(frozen=True)

    raw_text: str
    name: str
    value: str = ""
    secure: bool = False
    http_only: bool = False
    same_site: str | None = None
    has_expiration: bool = False
    max_age_seconds: int | None = None
    domain: str | None = None
    path: str | None = None


class ParsedJwt(BaseModel):
    """One parsed JWT's header/payload claims — `jwt_analyzer.py`'s
    intermediate representation. No cryptographic signature verification is
    ever performed (task brief's explicit instruction)."""

    model_config = ConfigDict(frozen=True)

    raw_text: str
    alg: str | None = None
    typ: str | None = None
    kid: str | None = None
    header_anomalies: tuple[str, ...] = ()
    exp: int | None = None
    iat: int | None = None
    iss: str | None = None
    aud: str | None = None
    is_expired: bool = False


class HeaderFinding(BaseModel):
    """`header_analyzer.py`'s per-header verdict. `severity=INFO` with no
    matched rule/missing-header issue is a real, reachable "well-configured
    header" outcome — not merely the absence of output."""

    model_config = ConfigDict(frozen=True)

    header_name: str
    raw_text: str = ""
    category: OwaspCategory
    severity: WebSecuritySeverity
    confidence: float = Field(ge=0.0, le=1.0)
    explanation: str
    recommendation: str | None = None
    matched_rule_ids: tuple[str, ...] = ()


class CookieFinding(BaseModel):
    """`cookie_analyzer.py`'s per-cookie verdict. Same "no risk found"
    reachable outcome as `HeaderFinding`."""

    model_config = ConfigDict(frozen=True)

    cookie: ParsedCookie
    category: OwaspCategory
    severity: WebSecuritySeverity
    confidence: float = Field(ge=0.0, le=1.0)
    explanation: str
    recommendation: str | None = None
    matched_issue_ids: tuple[str, ...] = ()


class JwtFinding(BaseModel):
    """`jwt_analyzer.py`'s per-token verdict. Same "no risk found" reachable
    outcome as `HeaderFinding`/`CookieFinding`."""

    model_config = ConfigDict(frozen=True)

    jwt: ParsedJwt
    category: OwaspCategory
    severity: WebSecuritySeverity
    confidence: float = Field(ge=0.0, le=1.0)
    explanation: str
    recommendation: str | None = None
    matched_issue_ids: tuple[str, ...] = ()


class MisconfigurationFinding(BaseModel):
    """`misconfiguration_detector.py`'s per-line verdict (directory listing,
    debug endpoints, weak TLS metadata, default-credential indicators,
    excessive information disclosure)."""

    model_config = ConfigDict(frozen=True)

    raw_text: str
    category: OwaspCategory
    severity: WebSecuritySeverity
    confidence: float = Field(ge=0.0, le=1.0)
    explanation: str
    recommendation: str | None = None
    matched_rule_ids: tuple[str, ...] = ()


class OwaspFinding(BaseModel):
    """`finding_generator.py`'s unified output shape — the task brief's
    exact named contract: "OWASP category, Severity, Confidence, Evidence
    references, Explanation, Recommended remediation." Every analyzer's
    narrower finding type (`HeaderFinding`/`CookieFinding`/`JwtFinding`/
    `MisconfigurationFinding`) is normalized into this one shape."""

    model_config = ConfigDict(frozen=True)

    category: OwaspCategory
    severity: WebSecuritySeverity
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_reference: str
    explanation: str
    recommended_remediation: str
    source: str


class WebSecurityAdvice(BaseModel):
    """The aggregate output — a single request in, a single
    `WebSecurityAdvice` out; no persisted case-evidence lifecycle to track
    (matching `docs/adr/0019`'s "advisor" framing, applied here)."""

    model_config = ConfigDict(frozen=True)

    header_findings: tuple[HeaderFinding, ...] = ()
    cookie_findings: tuple[CookieFinding, ...] = ()
    jwt_findings: tuple[JwtFinding, ...] = ()
    misconfiguration_findings: tuple[MisconfigurationFinding, ...] = ()
    owasp_findings: tuple[OwaspFinding, ...] = ()
    overall_risk_level: WebSecuritySeverity = WebSecuritySeverity.INFO
    overall_confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    overall_explanation: str = ""
    skipped_line_count: int = 0
    total_line_count: int = 0


class RiskDimensionScores(BaseModel):
    """The configurable, weighted dimensions `risk_assessment.py` combines
    into `WebSecurityAdvice.overall_risk_level`/`overall_confidence`."""

    model_config = ConfigDict(frozen=True)

    highest_severity_score: float = Field(ge=0.0, le=1.0)
    highest_confidence_score: float = Field(ge=0.0, le=1.0)
    finding_count_score: float = Field(ge=0.0, le=1.0)
    critical_category_score: float = Field(ge=0.0, le=1.0)
    corroboration_score: float = Field(ge=0.0, le=1.0)
