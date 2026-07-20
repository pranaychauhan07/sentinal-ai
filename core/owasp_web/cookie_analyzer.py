"""``CookieAnalyzer`` — runs every structural check in
`cookie_rules.DEFAULT_COOKIE_CHECKS` against one parsed `ParsedCookie`,
producing a single `CookieFinding` (the highest-severity issue found) or
`None` when no issue is found (a real, reachable "well-configured cookie"
outcome).

`parse_set_cookie_line` is a pure function extracting a `ParsedCookie` from
a raw `Set-Cookie: ...` header line — this package's cookie-attribute
counterpart to `core.linux_advisor.permission_parser`'s pure conversion
functions.
"""

from __future__ import annotations

import re

from core.owasp_web.cookie_rules import DEFAULT_COOKIE_CHECKS
from core.owasp_web.exceptions import MalformedHttpLineError
from core.owasp_web.models import CookieFinding, ParsedCookie, severity_rank

_SET_COOKIE_PREFIX = re.compile(r"^set-cookie\s*:\s*", re.IGNORECASE)


def parse_set_cookie_line(raw_text: str) -> ParsedCookie:
    """Parses a `Set-Cookie: name=value; Attr1; Attr2=Value2; ...` line.
    Raises `MalformedHttpLineError` if no `name=value` pair can be found —
    caught by `advisory_engine.py` and skipped, never fatal."""
    body = _SET_COOKIE_PREFIX.sub("", raw_text.strip())
    parts = [p.strip() for p in body.split(";") if p.strip()]
    if not parts or "=" not in parts[0]:
        raise MalformedHttpLineError(f"Set-Cookie line has no name=value pair: {raw_text!r}")

    name, _, value = parts[0].partition("=")
    attributes = {"secure": False, "http_only": False}
    same_site: str | None = None
    max_age: int | None = None
    has_expiration = False
    domain: str | None = None
    path: str | None = None

    for attribute in parts[1:]:
        key, _, attr_value = attribute.partition("=")
        key_lower = key.strip().lower()
        attr_value = attr_value.strip()
        if key_lower == "secure":
            attributes["secure"] = True
        elif key_lower == "httponly":
            attributes["http_only"] = True
        elif key_lower == "samesite":
            same_site = attr_value or None
        elif key_lower == "max-age":
            has_expiration = True
            try:
                max_age = int(attr_value)
            except ValueError:
                max_age = None
        elif key_lower == "expires":
            has_expiration = True
        elif key_lower == "domain":
            domain = attr_value or None
        elif key_lower == "path":
            path = attr_value or None

    return ParsedCookie(
        raw_text=raw_text,
        name=name.strip(),
        value=value.strip(),
        secure=attributes["secure"],
        http_only=attributes["http_only"],
        same_site=same_site,
        has_expiration=has_expiration,
        max_age_seconds=max_age,
        domain=domain,
        path=path,
    )


class CookieAnalyzer:
    def analyze(self, cookie: ParsedCookie) -> CookieFinding | None:
        issues = [check(cookie) for check in DEFAULT_COOKIE_CHECKS]
        found = [issue for issue in issues if issue is not None]
        if not found:
            return None
        highest = max(found, key=lambda issue: severity_rank(issue.severity))
        return CookieFinding(
            cookie=cookie,
            category=highest.category,
            severity=highest.severity,
            confidence=highest.confidence,
            explanation=highest.explanation,
            recommendation=highest.recommendation,
            matched_issue_ids=tuple(issue.issue_id for issue in found),
        )
