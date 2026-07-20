"""Default rule data for `header_analyzer.py`.

Two distinct kinds of check, deliberately not unified into one mechanism:

- **`MISSING_HEADER_SPECS`** — presence checks. A header being entirely
  absent cannot be expressed as a regex match against nonexistent text, so
  this is a structured lookup table `header_analyzer.py` walks directly,
  mirroring `core.linux_advisor.permission_parser`'s "pure function, not
  rule engine" precedent for structural (rather than pattern) checks.
- **`DEFAULT_HEADER_VALUE_RULES`** — pattern checks against a header that
  *is* present (e.g. a CSP containing `unsafe-inline`), evaluated via the
  generic `rule_engine.RuleEngine` against a synthesized `"Name: Value"`
  line — the task brief's named extensibility seam. Adding a new value
  quality check later means adding a `Rule` here; the engine never changes.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from core.owasp_web.models import MatcherKind, OwaspCategory, WebSecuritySeverity
from core.owasp_web.rule_engine import Matcher, Rule


class MissingHeaderSpec(BaseModel):
    """One security header this package checks for outright absence."""

    model_config = ConfigDict(frozen=True)

    header_name: str
    category: OwaspCategory
    severity: WebSecuritySeverity
    explanation: str
    recommendation: str


#: The task brief's six named security headers, checked for outright
#: absence. Case-insensitive lookup is performed by `header_analyzer.py`.
MISSING_HEADER_SPECS: tuple[MissingHeaderSpec, ...] = (
    MissingHeaderSpec(
        header_name="Content-Security-Policy",
        category=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
        severity=WebSecuritySeverity.MEDIUM,
        explanation=(
            "No Content-Security-Policy header was present — the browser has no "
            "restriction on which sources may load scripts/styles/frames, "
            "increasing exposure to injected-content attacks."
        ),
        recommendation=(
            "Add a Content-Security-Policy header restricting script/style/frame "
            "sources to a known allowlist (avoid 'unsafe-inline'/'unsafe-eval')."
        ),
    ),
    MissingHeaderSpec(
        header_name="Strict-Transport-Security",
        category=OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES,
        severity=WebSecuritySeverity.MEDIUM,
        explanation=(
            "No Strict-Transport-Security (HSTS) header was present — clients are "
            "not instructed to always use HTTPS, leaving room for downgrade/"
            "man-in-the-middle attacks on subsequent visits."
        ),
        recommendation=(
            "Add Strict-Transport-Security with a max-age of at least one year "
            "and includeSubDomains."
        ),
    ),
    MissingHeaderSpec(
        header_name="X-Frame-Options",
        category=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
        severity=WebSecuritySeverity.LOW,
        explanation=(
            "No X-Frame-Options header was present — the page can be embedded in "
            "a frame on another origin, enabling clickjacking."
        ),
        recommendation=(
            "Add X-Frame-Options: DENY or SAMEORIGIN (or an equivalent CSP "
            "frame-ancestors directive)."
        ),
    ),
    MissingHeaderSpec(
        header_name="X-Content-Type-Options",
        category=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
        severity=WebSecuritySeverity.LOW,
        explanation=(
            "No X-Content-Type-Options header was present — browsers may "
            "MIME-sniff responses, enabling content-type confusion attacks."
        ),
        recommendation="Add X-Content-Type-Options: nosniff.",
    ),
    MissingHeaderSpec(
        header_name="Referrer-Policy",
        category=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
        severity=WebSecuritySeverity.LOW,
        explanation=(
            "No Referrer-Policy header was present — full URLs (which may embed "
            "sensitive query parameters) may leak to third-party Referer headers."
        ),
        recommendation="Add Referrer-Policy: strict-origin-when-cross-origin (or stricter).",
    ),
    MissingHeaderSpec(
        header_name="Permissions-Policy",
        category=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
        severity=WebSecuritySeverity.INFO,
        explanation=(
            "No Permissions-Policy header was present — powerful browser features "
            "(camera, microphone, geolocation, ...) are not explicitly restricted."
        ),
        recommendation="Add a Permissions-Policy header disabling unneeded browser features.",
    ),
)


#: Value-quality rules, evaluated against a synthesized `"Name: Value"` line
#: for every header that *is* present.
DEFAULT_HEADER_VALUE_RULES: tuple[Rule, ...] = (
    Rule(
        id="csp_unsafe_inline",
        name="CSP allows 'unsafe-inline'",
        category=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
        severity=WebSecuritySeverity.MEDIUM,
        confidence=0.9,
        matcher=Matcher(kind=MatcherKind.REGEX, pattern=r"content-security-policy:.*unsafe-inline"),
        explanation=(
            "The Content-Security-Policy permits 'unsafe-inline' script/style "
            "execution, substantially weakening its protection against injected "
            "content."
        ),
        recommendation=(
            "Remove 'unsafe-inline' and use nonces/hashes for required inline scripts/styles."
        ),
        priority=80,
    ),
    Rule(
        id="csp_wildcard_source",
        name="CSP allows a wildcard source",
        category=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
        severity=WebSecuritySeverity.MEDIUM,
        confidence=0.85,
        matcher=Matcher(
            kind=MatcherKind.REGEX, pattern=r"content-security-policy:.*[\s'\"]\*(?!\S)"
        ),
        explanation=(
            "The Content-Security-Policy allows a wildcard '*' source, permitting "
            "content from any origin."
        ),
        recommendation="Restrict CSP source lists to a specific, known allowlist of origins.",
        priority=75,
    ),
    Rule(
        id="hsts_missing_max_age_or_short",
        name="HSTS missing or short max-age",
        category=OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES,
        severity=WebSecuritySeverity.LOW,
        confidence=0.8,
        matcher=Matcher(
            kind=MatcherKind.REGEX, pattern=r"strict-transport-security:(?!.*max-age=\d{7,})"
        ),
        explanation=(
            "The Strict-Transport-Security header is missing max-age or sets it "
            "below roughly one year (10,000,000+ seconds recommended)."
        ),
        recommendation="Set Strict-Transport-Security max-age to at least 31536000 (one year).",
        priority=60,
    ),
    Rule(
        id="hsts_missing_include_subdomains",
        name="HSTS missing includeSubDomains",
        category=OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES,
        severity=WebSecuritySeverity.INFO,
        confidence=0.7,
        matcher=Matcher(
            kind=MatcherKind.REGEX, pattern=r"strict-transport-security:(?!.*includesubdomains)"
        ),
        explanation=(
            "The Strict-Transport-Security header does not include "
            "includeSubDomains, leaving subdomains unprotected by the policy."
        ),
        recommendation="Add includeSubDomains to the Strict-Transport-Security header.",
        priority=40,
    ),
    Rule(
        id="x_frame_options_invalid_value",
        name="X-Frame-Options has a non-standard value",
        category=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
        severity=WebSecuritySeverity.LOW,
        confidence=0.75,
        matcher=Matcher(
            kind=MatcherKind.REGEX, pattern=r"x-frame-options:\s*(?!deny|sameorigin)\S"
        ),
        explanation=(
            "X-Frame-Options is set to a value other than DENY/SAMEORIGIN, which "
            "modern browsers may not honor consistently."
        ),
        recommendation="Set X-Frame-Options to DENY or SAMEORIGIN.",
        priority=50,
    ),
    Rule(
        id="referrer_policy_unsafe_url",
        name="Referrer-Policy set to unsafe-url",
        category=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
        severity=WebSecuritySeverity.LOW,
        confidence=0.85,
        matcher=Matcher(kind=MatcherKind.LITERAL_SUBSTRING, pattern="referrer-policy: unsafe-url"),
        explanation=(
            "Referrer-Policy is set to 'unsafe-url', always sending the full "
            "referrer URL (including any sensitive query parameters) cross-origin."
        ),
        recommendation="Use strict-origin-when-cross-origin or a stricter Referrer-Policy value.",
        priority=45,
    ),
    Rule(
        id="server_header_version_disclosure",
        name="Server header discloses version information",
        category=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
        severity=WebSecuritySeverity.LOW,
        confidence=0.7,
        matcher=Matcher(kind=MatcherKind.REGEX, pattern=r"(?:server|x-powered-by):\s*\S+/\d"),
        explanation=(
            "The Server/X-Powered-By header discloses specific software/version "
            "information, aiding an attacker in targeting known vulnerabilities."
        ),
        recommendation=(
            "Suppress or generalize the Server/X-Powered-By header (omit version numbers)."
        ),
        priority=55,
    ),
)
