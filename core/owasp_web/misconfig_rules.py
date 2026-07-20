"""Default `rule_engine.Rule` data set for `misconfiguration_detector.py` —
pattern-based checks over generic response-body/log/URL lines (directory
listing, debug endpoints, default-credential indicators, weak TLS
configuration metadata markers, excessive information disclosure). Adding a
new detection later means adding a `Rule` here; `rule_engine.py` never
changes.
"""

from __future__ import annotations

from core.owasp_web.models import MatcherKind, OwaspCategory, WebSecuritySeverity
from core.owasp_web.rule_engine import Matcher, Rule

DEFAULT_MISCONFIG_RULES: tuple[Rule, ...] = (
    Rule(
        id="directory_listing_enabled",
        name="Directory listing enabled",
        category=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
        severity=WebSecuritySeverity.MEDIUM,
        confidence=0.9,
        matcher=Matcher(kind=MatcherKind.REGEX, pattern=r"index of /\S*"),
        explanation=(
            "A response body appears to contain a directory listing ('Index of "
            "/...'), exposing the server's file structure to any visitor."
        ),
        recommendation="Disable directory listing/autoindex on the web server.",
        priority=70,
    ),
    Rule(
        id="debug_endpoint_exposed",
        name="Debug/diagnostic endpoint exposed",
        category=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
        severity=WebSecuritySeverity.HIGH,
        confidence=0.75,
        matcher=Matcher(
            kind=MatcherKind.REGEX,
            pattern=r"(?:^|[\s\"'])/(?:debug|actuator(?:/env|/health|/beans)?|_profiler|phpinfo\.php|console)(?:[/?\"'\s]|$)",
        ),
        explanation=(
            "A debug/diagnostic endpoint (e.g. /debug, /actuator, /_profiler, "
            "phpinfo.php) appears reachable, potentially exposing internals or "
            "an interactive console."
        ),
        recommendation="Disable or restrict debug/diagnostic endpoints in production.",
        priority=85,
    ),
    Rule(
        id="default_credentials_indicator",
        name="Default-credential indicator present",
        category=OwaspCategory.A07_AUTHENTICATION_FAILURES,
        severity=WebSecuritySeverity.HIGH,
        confidence=0.6,
        matcher=Matcher(
            kind=MatcherKind.REGEX,
            pattern=r"\b(?:admin[:/]admin|root[:/]root|user[:/]password|default password)\b",
        ),
        explanation=(
            "Content matching a common default-credential pattern was found, "
            "suggesting default or documented-example credentials may still work."
        ),
        recommendation=(
            "Ensure all default/example credentials are changed or disabled before deployment."
        ),
        priority=65,
    ),
    Rule(
        id="stack_trace_disclosure",
        name="Stack trace / verbose error disclosure",
        category=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
        severity=WebSecuritySeverity.MEDIUM,
        confidence=0.85,
        matcher=Matcher(
            kind=MatcherKind.REGEX,
            pattern=r"(?:traceback \(most recent call last\)|at\s+\S+\.\S+\(\S+\.java:\d+\)|"
            r"exception in thread|unhandled exception|fatal error:.*on line \d+)",
        ),
        explanation=(
            "A response/log line appears to contain a full stack trace or verbose "
            "error message, disclosing internal implementation details."
        ),
        recommendation=(
            "Return generic error messages to clients; log full detail server-side only."
        ),
        priority=60,
    ),
    Rule(
        id="weak_tls_protocol_metadata",
        name="Weak TLS protocol/cipher referenced",
        category=OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES,
        severity=WebSecuritySeverity.HIGH,
        confidence=0.8,
        matcher=Matcher(
            kind=MatcherKind.REGEX, pattern=r"\b(?:sslv2|sslv3|tls\s*1\.0|tls\s*1\.1|rc4|3des)\b"
        ),
        explanation=(
            "Configuration metadata references a deprecated/weak TLS protocol "
            "version or cipher (SSLv2/SSLv3/TLS 1.0/TLS 1.1/RC4/3DES)."
        ),
        recommendation="Disable deprecated TLS versions and weak ciphers; require TLS 1.2+.",
        priority=75,
    ),
    Rule(
        id="excessive_information_disclosure",
        name="Internal path or credential-shaped value disclosed",
        category=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
        severity=WebSecuritySeverity.LOW,
        confidence=0.55,
        matcher=Matcher(
            kind=MatcherKind.REGEX,
            pattern=r"(?:[cC]:\\\\[Uu]sers\\\\|/home/[a-zA-Z0-9_.-]+/|/var/www/|internal[_-]?ip|10\.\d{1,3}\.\d{1,3}\.\d{1,3})",
        ),
        explanation=(
            "A response/log line appears to disclose an internal filesystem path, "
            "internal IP address, or similar implementation detail."
        ),
        recommendation=(
            "Scrub internal paths/addresses from any response or error message returned to clients."
        ),
        priority=40,
    ),
)
