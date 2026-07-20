"""Narrow exception hierarchy for `core/owasp_security` — constitution §5
("every tool module defines its own narrow exception classes"), mirroring
`core/owasp_web/exceptions.py`'s pattern exactly.
"""

from __future__ import annotations

from core.exceptions import ValidationError


class SastError(ValidationError):
    """Base class for every exception this package raises deliberately."""

    code = "SAST_ERROR"


class UnsupportedLanguageError(SastError):
    """The artifact's language could not be detected, or was detected as a
    language this framework does not recognize at all — caught by
    `analysis_engine.py` and converted into a degraded, zero-finding
    `SastAdvice` rather than aborting (constitution §1.7)."""

    code = "UNSUPPORTED_LANGUAGE"


class AstParseError(SastError):
    """Python source could not be parsed into an AST (a genuine syntax
    error, or a source file too malformed to tokenize) — caught by
    `analysis_engine.py` and converted into a degraded result
    (`SastAdvice.parse_degraded=True`), never fatal to the whole artifact."""

    code = "AST_PARSE_ERROR"


class OversizedSourceInputError(SastError):
    """The source artifact presented to
    `analysis_engine.SourceCodeAnalysisEngine` exceeds the configured
    maximum line/character count — the resource-exhaustion guard for
    pathological inputs (constitution §10), mirroring
    `core.owasp_web.exceptions.OversizedWebSecurityInputError`'s identical
    reasoning."""

    code = "OVERSIZED_SOURCE_INPUT"
