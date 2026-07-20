"""Pure, structural cookie-attribute checks for `cookie_analyzer.py`.

Cookie attributes (`Secure`/`HttpOnly`/`SameSite`/expiration/`Domain`/`Path`)
are structural properties of a parsed `Set-Cookie` line, not a text pattern a
regex-based `rule_engine.RuleEngine` naturally expresses — mirroring
`core.linux_advisor.permission_parser`'s "pure function, not rule engine"
precedent for structural (rather than pattern) checks. Each check below
returns a `CookieIssue | None`; `cookie_analyzer.py` collects every non-`None`
result for one parsed cookie.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from core.owasp_web.models import OwaspCategory, ParsedCookie, WebSecuritySeverity

#: A cookie whose max-age exceeds this many seconds (~1 year) is flagged as
#: an excessive-expiration finding.
_EXCESSIVE_MAX_AGE_SECONDS = 365 * 24 * 60 * 60

#: Cookie name substrings suggestive of session/authentication material —
#: used only to raise severity on an otherwise-generic missing-attribute
#: finding, never to gate whether the check runs at all.
_SESSION_LIKE_NAME_HINTS: frozenset[str] = frozenset(
    {"session", "sess", "auth", "token", "jwt", "sid", "login"}
)


class CookieIssue(BaseModel):
    """One structural cookie-attribute issue."""

    model_config = ConfigDict(frozen=True)

    issue_id: str
    category: OwaspCategory
    severity: WebSecuritySeverity
    confidence: float
    explanation: str
    recommendation: str


def _looks_session_like(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in _SESSION_LIKE_NAME_HINTS)


def check_secure_missing(cookie: ParsedCookie) -> CookieIssue | None:
    if cookie.secure:
        return None
    severity = (
        WebSecuritySeverity.HIGH if _looks_session_like(cookie.name) else WebSecuritySeverity.MEDIUM
    )
    return CookieIssue(
        issue_id="cookie_missing_secure",
        category=OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES,
        severity=severity,
        confidence=0.9,
        explanation=(
            f"Cookie '{cookie.name}' is missing the Secure attribute — it may be "
            "transmitted over plain HTTP, exposing it to network interception."
        ),
        recommendation="Set the Secure attribute on every cookie carrying session/auth data.",
    )


def check_http_only_missing(cookie: ParsedCookie) -> CookieIssue | None:
    if cookie.http_only:
        return None
    severity = (
        WebSecuritySeverity.HIGH if _looks_session_like(cookie.name) else WebSecuritySeverity.MEDIUM
    )
    return CookieIssue(
        issue_id="cookie_missing_http_only",
        category=OwaspCategory.A07_AUTHENTICATION_FAILURES,
        severity=severity,
        confidence=0.9,
        explanation=(
            f"Cookie '{cookie.name}' is missing the HttpOnly attribute — "
            "client-side script (including an injected XSS payload) can read it."
        ),
        recommendation=(
            "Set the HttpOnly attribute on every cookie not required by client-side script."
        ),
    )


def check_samesite_issue(cookie: ParsedCookie) -> CookieIssue | None:
    same_site = (cookie.same_site or "").strip().lower()
    if not same_site:
        return CookieIssue(
            issue_id="cookie_missing_samesite",
            category=OwaspCategory.A01_BROKEN_ACCESS_CONTROL,
            severity=WebSecuritySeverity.MEDIUM,
            confidence=0.85,
            explanation=(
                f"Cookie '{cookie.name}' has no SameSite attribute — browser "
                "defaults vary, and the cookie may be sent on cross-site requests, "
                "increasing CSRF exposure."
            ),
            recommendation="Set SameSite=Lax (or Strict) explicitly.",
        )
    if same_site == "none" and not cookie.secure:
        return CookieIssue(
            issue_id="cookie_samesite_none_without_secure",
            category=OwaspCategory.A01_BROKEN_ACCESS_CONTROL,
            severity=WebSecuritySeverity.HIGH,
            confidence=0.9,
            explanation=(
                f"Cookie '{cookie.name}' sets SameSite=None without Secure — modern "
                "browsers reject this combination or treat it unpredictably, and it "
                "permits cross-site sending over plain HTTP where accepted."
            ),
            recommendation=(
                "Pair SameSite=None with the Secure attribute, or use Lax/Strict instead."
            ),
        )
    return None


def check_excessive_expiration(cookie: ParsedCookie) -> CookieIssue | None:
    if cookie.max_age_seconds is None or cookie.max_age_seconds <= _EXCESSIVE_MAX_AGE_SECONDS:
        return None
    return CookieIssue(
        issue_id="cookie_excessive_expiration",
        category=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
        severity=WebSecuritySeverity.LOW,
        confidence=0.75,
        explanation=(
            f"Cookie '{cookie.name}' has a Max-Age of {cookie.max_age_seconds} seconds "
            "(over one year), keeping it valid far longer than most sessions warrant."
        ),
        recommendation=(
            "Reduce the cookie's Max-Age/Expires to the shortest period the use case requires."
        ),
    )


def check_broad_domain(cookie: ParsedCookie) -> CookieIssue | None:
    if not cookie.domain or not cookie.domain.startswith("."):
        return None
    labels = [label for label in cookie.domain.strip(".").split(".") if label]
    if len(labels) > 2:
        return None
    return CookieIssue(
        issue_id="cookie_broad_domain",
        category=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
        severity=WebSecuritySeverity.LOW,
        confidence=0.6,
        explanation=(
            f"Cookie '{cookie.name}' sets Domain={cookie.domain}, scoping it to the "
            "entire parent domain and every subdomain rather than the issuing host."
        ),
        recommendation="Scope the cookie's Domain attribute as narrowly as the use case allows.",
    )


#: Every structural cookie check, run in order by `cookie_analyzer.py`.
DEFAULT_COOKIE_CHECKS = (
    check_secure_missing,
    check_http_only_missing,
    check_samesite_issue,
    check_excessive_expiration,
    check_broad_domain,
)
