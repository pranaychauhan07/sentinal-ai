"""Domain models for `core/owasp_security` — blueprint §7's OWASP Security
Agent ("source code / API static review... detect SQLi/XSS/broken-auth
patterns, map to OWASP Top-10 (2021)...").

Owns its own severity scale (`SastSeverity`) and OWASP category enum
(`OwaspCategory`) rather than reusing `core.owasp_web.models.OwaspCategory`
or any other sibling leaf's — matching the "each leaf owns its own copy"
precedent (`docs/adr/0017` point 2 / `docs/adr/0018` point 2 / `docs/adr/0019`
point 4 / `docs/adr/0020` point 4).
"""

from __future__ import annotations

from enum import IntEnum, StrEnum

from pydantic import BaseModel, ConfigDict, Field


class SourceLanguage(StrEnum):
    """Languages this framework recognizes. `UNKNOWN` is a real, reachable
    outcome (constitution §1.7) — never silently treated as Python."""

    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    UNKNOWN = "unknown"


#: Languages `python_ast_analyzer.py` handles via genuine AST parsing.
#: Every other supported language is handled by `pattern_analyzer.py`
#: (docs/adr/0021 point "why Python gets AST").
AST_SUPPORTED_LANGUAGES: frozenset[SourceLanguage] = frozenset({SourceLanguage.PYTHON})


class SastSeverity(StrEnum):
    """This package's own severity scale — never shared with
    `core.owasp_web.models.WebSecuritySeverity` or any other sibling leaf's."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_SEVERITY_ORDER: dict[SastSeverity, int] = {
    SastSeverity.INFO: 0,
    SastSeverity.LOW: 1,
    SastSeverity.MEDIUM: 2,
    SastSeverity.HIGH: 3,
    SastSeverity.CRITICAL: 4,
}


def severity_rank(severity: SastSeverity) -> int:
    """Deterministic ordinal for a `SastSeverity` — the one place this
    ranking is defined (constitution §2)."""
    return _SEVERITY_ORDER[severity]


def highest_severity(severities: list[SastSeverity]) -> SastSeverity:
    if not severities:
        return SastSeverity.INFO
    return max(severities, key=severity_rank)


class OwaspCategory(StrEnum):
    """The ten OWASP Top 10 (2021) categories — this package's own copy,
    never imported from `core.owasp_web.models.OwaspCategory` (leaves never
    share code sideways, docs/dependency-rules.md rule 10)."""

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


class VulnerabilityCategory(StrEnum):
    """The task's fifteen named detection categories — each mapped to an
    `OwaspCategory` and a CWE id via `CATEGORY_OWASP_MAP`/`CATEGORY_CWE_MAP`
    below, the single source of truth for that mapping (constitution §2,
    "a magic number/mapping that appears in two places will eventually be
    updated in only one")."""

    SQL_INJECTION = "sql_injection"
    XSS = "cross_site_scripting"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "server_side_request_forgery"
    HARDCODED_SECRETS = "hardcoded_secrets"
    WEAK_CRYPTOGRAPHY = "weak_cryptography"
    INSECURE_RANDOMNESS = "insecure_randomness"
    UNSAFE_DESERIALIZATION = "unsafe_deserialization"
    BROKEN_AUTHENTICATION = "broken_authentication"
    MISSING_INPUT_VALIDATION = "missing_input_validation"
    DANGEROUS_FILE_OPERATIONS = "dangerous_file_operations"
    OPEN_REDIRECT = "open_redirect"
    SENSITIVE_INFORMATION_EXPOSURE = "sensitive_information_exposure"
    INSECURE_CONFIGURATION = "insecure_configuration"


#: `VulnerabilityCategory` -> `OwaspCategory` — every category has exactly
#: one primary OWASP mapping used for reporting/grouping.
CATEGORY_OWASP_MAP: dict[VulnerabilityCategory, OwaspCategory] = {
    VulnerabilityCategory.SQL_INJECTION: OwaspCategory.A03_INJECTION,
    VulnerabilityCategory.XSS: OwaspCategory.A03_INJECTION,
    VulnerabilityCategory.COMMAND_INJECTION: OwaspCategory.A03_INJECTION,
    VulnerabilityCategory.PATH_TRAVERSAL: OwaspCategory.A01_BROKEN_ACCESS_CONTROL,
    VulnerabilityCategory.SSRF: OwaspCategory.A10_SSRF,
    VulnerabilityCategory.HARDCODED_SECRETS: OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES,
    VulnerabilityCategory.WEAK_CRYPTOGRAPHY: OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES,
    VulnerabilityCategory.INSECURE_RANDOMNESS: OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES,
    VulnerabilityCategory.UNSAFE_DESERIALIZATION: (
        OwaspCategory.A08_SOFTWARE_DATA_INTEGRITY_FAILURES
    ),
    VulnerabilityCategory.BROKEN_AUTHENTICATION: OwaspCategory.A07_AUTHENTICATION_FAILURES,
    VulnerabilityCategory.MISSING_INPUT_VALIDATION: OwaspCategory.A04_INSECURE_DESIGN,
    VulnerabilityCategory.DANGEROUS_FILE_OPERATIONS: OwaspCategory.A01_BROKEN_ACCESS_CONTROL,
    VulnerabilityCategory.OPEN_REDIRECT: OwaspCategory.A01_BROKEN_ACCESS_CONTROL,
    VulnerabilityCategory.SENSITIVE_INFORMATION_EXPOSURE: (
        OwaspCategory.A09_LOGGING_MONITORING_FAILURES
    ),
    VulnerabilityCategory.INSECURE_CONFIGURATION: OwaspCategory.A05_SECURITY_MISCONFIGURATION,
}

#: `VulnerabilityCategory` -> representative CWE id — the task's named "CWE
#: Mapping" requirement. One representative CWE per category (the most
#: common/canonical id), not an exhaustive multi-CWE mapping.
CATEGORY_CWE_MAP: dict[VulnerabilityCategory, str] = {
    VulnerabilityCategory.SQL_INJECTION: "CWE-89",
    VulnerabilityCategory.XSS: "CWE-79",
    VulnerabilityCategory.COMMAND_INJECTION: "CWE-78",
    VulnerabilityCategory.PATH_TRAVERSAL: "CWE-22",
    VulnerabilityCategory.SSRF: "CWE-918",
    VulnerabilityCategory.HARDCODED_SECRETS: "CWE-798",
    VulnerabilityCategory.WEAK_CRYPTOGRAPHY: "CWE-327",
    VulnerabilityCategory.INSECURE_RANDOMNESS: "CWE-330",
    VulnerabilityCategory.UNSAFE_DESERIALIZATION: "CWE-502",
    VulnerabilityCategory.BROKEN_AUTHENTICATION: "CWE-287",
    VulnerabilityCategory.MISSING_INPUT_VALIDATION: "CWE-20",
    VulnerabilityCategory.DANGEROUS_FILE_OPERATIONS: "CWE-73",
    VulnerabilityCategory.OPEN_REDIRECT: "CWE-601",
    VulnerabilityCategory.SENSITIVE_INFORMATION_EXPOSURE: "CWE-200",
    VulnerabilityCategory.INSECURE_CONFIGURATION: "CWE-16",
}


class MatcherKind(StrEnum):
    """The tagged-union discriminator for `rule_engine.Rule.matcher`. Adds
    `ast_predicate` to the `regex`/`literal_substring`/`callable_signature`
    shape ADR-0019/0020 established — dispatches to a named AST-visitor
    predicate instead of a text predicate."""

    REGEX = "regex"
    LITERAL_SUBSTRING = "literal_substring"
    CALLABLE_SIGNATURE = "callable_signature"
    AST_PREDICATE = "ast_predicate"


class RulePriority(IntEnum):
    LOWEST = 0
    LOW = 25
    MEDIUM = 50
    HIGH = 75
    HIGHEST = 100


class RuleMatch(BaseModel):
    """One `rule_engine.RuleEngine` match against source text or an AST."""

    model_config = ConfigDict(frozen=True)

    rule_id: str
    category: VulnerabilityCategory
    owasp_category: OwaspCategory
    cwe_id: str
    severity: SastSeverity
    confidence: float = Field(ge=0.0, le=1.0)
    explanation: str
    recommendation: str | None = None
    matched_text: str = ""
    line_number: int | None = None


class SourceFinding(BaseModel):
    """One detected issue in one analyzed file — `python_ast_analyzer.py`'s/
    `pattern_analyzer.py`'s output shape, before `finding_generator.py`
    normalizes it into the unified `SastFinding`. `severity=INFO`/no matches
    is a real, reachable "clean file" outcome, never merely absent output."""

    model_config = ConfigDict(frozen=True)

    file_path: str
    line_number: int | None = None
    category: VulnerabilityCategory
    owasp_category: OwaspCategory
    cwe_id: str
    severity: SastSeverity
    confidence: float = Field(ge=0.0, le=1.0)
    code_snippet: str = ""
    explanation: str
    recommendation: str | None = None
    matched_rule_ids: tuple[str, ...] = ()
    is_ast_based: bool = False


class SecureCodingRecommendation(BaseModel):
    """One secure-coding recommendation — either triggered by a specific
    finding (`is_baseline=False`, `related_subject` names what triggered it)
    or a baseline recommendation surfaced regardless of findings
    (`is_baseline=True`), mirroring `core.linux_advisor.hardening_advisor`'s
    established shape."""

    model_config = ConfigDict(frozen=True)

    category: VulnerabilityCategory
    recommendation: str
    rationale: str
    priority: int = Field(ge=1, le=5)
    is_baseline: bool = False
    related_subject: str | None = None


class SastFinding(BaseModel):
    """`finding_generator.py`'s unified output shape — the task brief's
    exact named contract: OWASP category, CWE id, severity, confidence,
    evidence reference, explanation, recommended remediation."""

    model_config = ConfigDict(frozen=True)

    category: VulnerabilityCategory
    owasp_category: OwaspCategory
    cwe_id: str
    severity: SastSeverity
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_reference: str
    explanation: str
    recommended_remediation: str
    source: str


class SastAdvice(BaseModel):
    """The aggregate output — a single source file in, a single
    `SastAdvice` out; no persisted case-evidence lifecycle to track
    (matching `docs/adr/0019`/`docs/adr/0020`'s "advisor" framing)."""

    model_config = ConfigDict(frozen=True)

    language: SourceLanguage = SourceLanguage.UNKNOWN
    source_findings: tuple[SourceFinding, ...] = ()
    secure_coding_recommendations: tuple[SecureCodingRecommendation, ...] = ()
    sast_findings: tuple[SastFinding, ...] = ()
    overall_risk_level: SastSeverity = SastSeverity.INFO
    overall_confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    overall_explanation: str = ""
    parse_degraded: bool = False
    total_line_count: int = 0


class RiskDimensionScores(BaseModel):
    model_config = ConfigDict(frozen=True)

    highest_severity_score: float = Field(ge=0.0, le=1.0)
    highest_confidence_score: float = Field(ge=0.0, le=1.0)
    finding_count_score: float = Field(ge=0.0, le=1.0)
    critical_category_score: float = Field(ge=0.0, le=1.0)
    corroboration_score: float = Field(ge=0.0, le=1.0)
