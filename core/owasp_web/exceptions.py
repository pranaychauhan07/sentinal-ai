"""Narrow exception hierarchy for `core/owasp_web` — constitution §5
("every tool module defines its own narrow exception classes ... callers
need to be able to catch precisely"), mirroring
`core/linux_advisor/exceptions.py`'s pattern exactly.
"""

from __future__ import annotations

from core.exceptions import ValidationError


class WebSecurityError(ValidationError):
    """Base class for every exception this package raises deliberately."""

    code = "WEB_SECURITY_ERROR"


class MalformedHttpLineError(WebSecurityError):
    """A candidate header/cookie/request-line could not be parsed into its
    expected shape — `advisory_engine.py` catches this and skips the line
    rather than aborting the whole artifact (constitution §1.7)."""

    code = "MALFORMED_HTTP_LINE"


class MalformedJwtError(WebSecurityError):
    """A candidate JWT string is not the expected `header.payload.signature`
    shape, or its header/payload segment is not valid base64url-encoded
    JSON. No cryptographic verification is ever attempted (task brief's
    explicit instruction) — this is a pure structural-decode failure."""

    code = "MALFORMED_JWT"


class OversizedWebSecurityInputError(WebSecurityError):
    """The evidence artifact presented to
    `advisory_engine.WebSecurityAdvisoryEngine` exceeds the configured
    maximum line/character count — the resource-exhaustion guard for
    pathological inputs (constitution §10), mirroring
    `core.linux_advisor.exceptions.OversizedLinuxAdvisorInputError`'s
    identical reasoning."""

    code = "OVERSIZED_WEB_SECURITY_INPUT"
