"""Narrow exception hierarchy for `core/linux_advisor` — constitution §5
("every tool module defines its own narrow exception classes ... callers
need to be able to catch precisely"), mirroring `core/vulnerabilities/
exceptions.py`'s pattern exactly.
"""

from __future__ import annotations

from core.exceptions import ValidationError


class LinuxAdvisorError(ValidationError):
    """Base class for every exception this package raises deliberately."""

    code = "LINUX_ADVISOR_ERROR"


class InvalidOctalModeError(LinuxAdvisorError):
    """A candidate octal permission string is not 3-4 digits in `0-7`."""

    code = "INVALID_OCTAL_MODE"


class InvalidPermissionStringError(LinuxAdvisorError):
    """An `ls -l`-style permission string is not the expected 10-character
    shape (or has an unrecognized file-type/special-bit character)."""

    code = "INVALID_PERMISSION_STRING"


class InvalidSymbolicModeError(LinuxAdvisorError):
    """A symbolic `chmod` mode string (`u+x`, `go-w`, ...) does not match the
    `[ugoa]*[+-=][rwxXst]+` grammar."""

    code = "INVALID_SYMBOLIC_MODE"


class InvalidUmaskError(LinuxAdvisorError):
    """A candidate umask value is not a valid 3-4 digit octal mask."""

    code = "INVALID_UMASK"


class MalformedCommandError(LinuxAdvisorError):
    """A raw command line could not be tokenized (unbalanced quoting) —
    `command_analyzer.py` catches this and skips the line rather than
    aborting the whole artifact (constitution §1.7)."""

    code = "MALFORMED_COMMAND"


class OversizedLinuxAdvisorInputError(LinuxAdvisorError):
    """The evidence artifact presented to
    `advisory_engine.LinuxSecurityAdvisoryEngine` exceeds the configured
    maximum line/character count — the resource-exhaustion guard for
    pathological inputs (constitution §10), mirroring
    `core.linux_security.exceptions`'s identical reasoning."""

    code = "OVERSIZED_LINUX_ADVISOR_INPUT"
