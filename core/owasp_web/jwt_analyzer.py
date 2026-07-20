"""``JwtAnalyzer`` — decodes a JWT's header/payload claims (no cryptographic
signature verification, per the task brief's explicit instruction) and flags
algorithm, expiration, issuer, audience, and header-anomaly issues.

`parse_jwt` is a pure function: base64url-decodes the header and payload
segments as JSON. A structurally invalid token (wrong segment count, invalid
base64, non-JSON payload) raises `MalformedJwtError` — the caller
(`advisory_engine.py`) catches this and skips the line, never fatal to the
whole artifact.
"""

from __future__ import annotations

import base64
import binascii
import json
import time

from core.owasp_web.exceptions import MalformedJwtError
from core.owasp_web.models import (
    JwtFinding,
    OwaspCategory,
    ParsedJwt,
    WebSecuritySeverity,
    severity_rank,
)

#: JWT header fields beyond `alg`/`typ`/`kid` that are legitimate but
#: security-relevant enough to flag as an "anomaly" worth an analyst's
#: attention (e.g. `jku`/`jwk` enable key-confusion attacks if the verifier
#: trusts an attacker-supplied key source).
_NOTABLE_HEADER_FIELDS: frozenset[str] = frozenset({"jku", "jwk", "x5u", "x5c", "crit"})

#: Algorithms treated as critically insecure regardless of context.
_CRITICAL_ALGORITHMS: frozenset[str] = frozenset({"none", ""})


def _b64url_decode(segment: str) -> bytes:
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError) as exc:
        raise MalformedJwtError(f"JWT segment is not valid base64url: {exc}") from exc


def parse_jwt(raw_text: str) -> ParsedJwt:
    """Parses a raw `header.payload.signature` JWT string. Never verifies
    the signature — this package performs no cryptographic operations."""
    parts = raw_text.strip().split(".")
    if len(parts) != 3 or not all(parts):
        raise MalformedJwtError("JWT does not have the expected header.payload.signature shape.")

    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise MalformedJwtError(f"JWT header/payload segment is not valid JSON: {exc}") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise MalformedJwtError("JWT header/payload segment did not decode to a JSON object.")

    anomalies = tuple(sorted(_NOTABLE_HEADER_FIELDS & header.keys()))
    exp = payload.get("exp")
    is_expired = isinstance(exp, int | float) and exp < time.time()

    return ParsedJwt(
        raw_text=raw_text,
        alg=header.get("alg"),
        typ=header.get("typ"),
        kid=header.get("kid"),
        header_anomalies=anomalies,
        exp=int(exp) if isinstance(exp, int | float) else None,
        iat=int(payload["iat"]) if isinstance(payload.get("iat"), int | float) else None,
        iss=payload.get("iss"),
        aud=str(payload["aud"]) if payload.get("aud") is not None else None,
        is_expired=bool(is_expired),
    )


class JwtAnalyzer:
    def analyze(self, jwt: ParsedJwt) -> JwtFinding | None:
        issues: list[tuple[str, OwaspCategory, WebSecuritySeverity, str, str]] = []

        alg = (jwt.alg or "").strip().lower()
        if alg in _CRITICAL_ALGORITHMS:
            issues.append(
                (
                    "jwt_none_or_missing_algorithm",
                    OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES,
                    WebSecuritySeverity.CRITICAL,
                    "The JWT's algorithm is 'none' or missing, meaning the token "
                    "carries no cryptographic protection at all.",
                    "Reject tokens with alg=none; require and verify a strong signing algorithm.",
                )
            )

        if jwt.exp is None:
            issues.append(
                (
                    "jwt_missing_expiration",
                    OwaspCategory.A07_AUTHENTICATION_FAILURES,
                    WebSecuritySeverity.HIGH,
                    "The JWT has no 'exp' claim, so it never expires once issued.",
                    "Always set a short, enforced 'exp' claim on issued tokens.",
                )
            )
        elif jwt.is_expired:
            issues.append(
                (
                    "jwt_expired",
                    OwaspCategory.A07_AUTHENTICATION_FAILURES,
                    WebSecuritySeverity.INFO,
                    "The JWT's 'exp' claim is in the past (expired).",
                    "Ensure the verifying service rejects expired tokens.",
                )
            )

        if not jwt.iss:
            issues.append(
                (
                    "jwt_missing_issuer",
                    OwaspCategory.A07_AUTHENTICATION_FAILURES,
                    WebSecuritySeverity.MEDIUM,
                    "The JWT has no 'iss' (issuer) claim, making issuer validation impossible.",
                    "Include and validate an 'iss' claim against an expected issuer.",
                )
            )
        if not jwt.aud:
            issues.append(
                (
                    "jwt_missing_audience",
                    OwaspCategory.A07_AUTHENTICATION_FAILURES,
                    WebSecuritySeverity.MEDIUM,
                    "The JWT has no 'aud' (audience) claim, making audience validation impossible.",
                    "Include and validate an 'aud' claim against the intended recipient service.",
                )
            )
        if jwt.header_anomalies:
            issues.append(
                (
                    "jwt_header_anomaly",
                    OwaspCategory.A08_SOFTWARE_DATA_INTEGRITY_FAILURES,
                    WebSecuritySeverity.HIGH,
                    "The JWT header includes "
                    f"{', '.join(jwt.header_anomalies)}, which can enable key-confusion "
                    "attacks if the verifier trusts an attacker-supplied key source.",
                    "Never resolve verification keys from attacker-controlled header fields "
                    "(jku/jwk/x5u/x5c); use a fixed, trusted key set.",
                )
            )

        if not issues:
            return None

        highest = max(issues, key=lambda i: severity_rank(i[2]))
        return JwtFinding(
            jwt=jwt,
            category=highest[1],
            severity=highest[2],
            confidence=0.85,
            explanation=highest[3],
            recommendation=highest[4],
            matched_issue_ids=tuple(i[0] for i in issues),
        )
