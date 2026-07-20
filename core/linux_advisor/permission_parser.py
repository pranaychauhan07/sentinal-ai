"""Pure permission-parsing functions — no I/O, no classes needed beyond the
shared `PermissionAnalysis` model. Every function here is a pure conversion:
octal <-> rwx triplets (both directions), `ls -l` permission-string parsing
(including file-type and special-bit characters), symbolic `chmod` mode
application, and `umask` interpretation.

Every malformed-input path raises a narrow `core.linux_advisor.exceptions`
type rather than guessing — callers (`command_analyzer.py`,
`advisory_engine.py`) catch these and skip just the offending line
(constitution §1.7).
"""

from __future__ import annotations

import re

from core.linux_advisor.exceptions import (
    InvalidOctalModeError,
    InvalidPermissionStringError,
    InvalidSymbolicModeError,
    InvalidUmaskError,
)
from core.linux_advisor.models import PermissionAnalysis

#: `ls -l`-recognized leading file-type characters.
_VALID_FILE_TYPES = frozenset("-dlbcpsD")

#: Owner/group execute-position characters and what they mean:
#: (is_executable, has_special_bit).
_OWNER_GROUP_EXEC_MAP: dict[str, tuple[bool, bool]] = {
    "x": (True, False),
    "s": (True, True),
    "S": (False, True),
    "-": (False, False),
}

#: Other execute-position characters (sticky bit instead of setuid/setgid).
_OTHER_EXEC_MAP: dict[str, tuple[bool, bool]] = {
    "x": (True, False),
    "t": (True, True),
    "T": (False, True),
    "-": (False, False),
}

_SYMBOLIC_MODE_PATTERN = re.compile(r"^[ugoa]*[+\-=][rwxXst]*(,[ugoa]*[+\-=][rwxXst]*)*$")


def octal_digit_to_rwx(digit: int) -> str:
    """One octal digit (0-7) -> its 3-char rwx representation."""
    if not (0 <= digit <= 7):
        raise InvalidOctalModeError(f"Octal digit must be 0-7, got {digit!r}.")
    return f"{'r' if digit & 4 else '-'}{'w' if digit & 2 else '-'}{'x' if digit & 1 else '-'}"


def rwx_to_octal_digit(rwx: str) -> int:
    """3-char rwx string (e.g. 'rwx', 'r--', '-w-') -> its octal digit."""
    if len(rwx) != 3:
        raise InvalidOctalModeError(f"rwx triplet must be exactly 3 characters, got {rwx!r}.")
    r, w, x = rwx[0], rwx[1], rwx[2]
    if r not in "r-" or w not in "w-" or x not in "x-":
        raise InvalidOctalModeError(f"Invalid rwx triplet: {rwx!r}.")
    value = 0
    if r == "r":
        value |= 4
    if w == "w":
        value |= 2
    if x == "x":
        value |= 1
    return value


def parse_octal_mode(mode: str) -> tuple[str, str, str, bool, bool, bool]:
    """Parses a 3- or 4-digit octal mode string ('755', '0755', '4755')
    into `(owner_rwx, group_rwx, other_rwx, setuid, setgid, sticky)`.
    Raises `InvalidOctalModeError` on anything else (wrong length, a
    non-octal digit, empty string)."""
    if not mode or not mode.isdigit() or len(mode) not in (3, 4):
        raise InvalidOctalModeError(
            f"Octal mode must be 3 or 4 digits (e.g. '755', '4755'), got {mode!r}."
        )
    if any(ch not in "01234567" for ch in mode):
        raise InvalidOctalModeError(f"Octal mode contains a non-octal digit: {mode!r}.")

    special_digit = int(mode[0]) if len(mode) == 4 else 0
    owner_digit, group_digit, other_digit = (int(d) for d in mode[-3:])

    setuid = bool(special_digit & 4)
    setgid = bool(special_digit & 2)
    sticky = bool(special_digit & 1)

    return (
        octal_digit_to_rwx(owner_digit),
        octal_digit_to_rwx(group_digit),
        octal_digit_to_rwx(other_digit),
        setuid,
        setgid,
        sticky,
    )


def format_octal_mode(
    owner_rwx: str,
    group_rwx: str,
    other_rwx: str,
    *,
    setuid: bool = False,
    setgid: bool = False,
    sticky: bool = False,
) -> str:
    """Inverse of `parse_octal_mode` — three rwx triplets (+ special bits)
    -> a 3- or 4-digit octal mode string (4 digits only if any special bit
    is set)."""
    owner_digit = rwx_to_octal_digit(owner_rwx)
    group_digit = rwx_to_octal_digit(group_rwx)
    other_digit = rwx_to_octal_digit(other_rwx)
    special_digit = (4 if setuid else 0) | (2 if setgid else 0) | (1 if sticky else 0)
    if special_digit:
        return f"{special_digit}{owner_digit}{group_digit}{other_digit}"
    return f"{owner_digit}{group_digit}{other_digit}"


def parse_ls_permission_string(perm_string: str) -> PermissionAnalysis:
    """Parses the 10-character `ls -l` permission-string form
    (`-rwxr-xr-x`, `drwxrwxrwt`, `lrwxrwxrwx`, ...) into a full
    `PermissionAnalysis`. Raises `InvalidPermissionStringError` if the
    string isn't exactly 10 characters, has an unrecognized leading
    file-type character, or has an invalid r/w/exec character in any
    position."""
    if len(perm_string) != 10:
        raise InvalidPermissionStringError(
            f"ls -l permission string must be exactly 10 characters, got "
            f"{len(perm_string)} in {perm_string!r}."
        )
    file_type = perm_string[0]
    if file_type not in _VALID_FILE_TYPES:
        raise InvalidPermissionStringError(f"Unrecognized file-type character: {file_type!r}.")

    owner_rwx, owner_exec_char = perm_string[1:3], perm_string[3]
    group_rwx, group_exec_char = perm_string[4:6], perm_string[6]
    other_rwx, other_exec_char = perm_string[7:9], perm_string[9]

    if owner_exec_char not in _OWNER_GROUP_EXEC_MAP:
        raise InvalidPermissionStringError(f"Invalid owner execute char: {owner_exec_char!r}.")
    if group_exec_char not in _OWNER_GROUP_EXEC_MAP:
        raise InvalidPermissionStringError(f"Invalid group execute char: {group_exec_char!r}.")
    if other_exec_char not in _OTHER_EXEC_MAP:
        raise InvalidPermissionStringError(f"Invalid other execute char: {other_exec_char!r}.")

    for label, rw in (("owner", owner_rwx), ("group", group_rwx), ("other", other_rwx)):
        if rw[0] not in "r-" or rw[1] not in "w-":
            raise InvalidPermissionStringError(f"Invalid {label} read/write characters: {rw!r}.")

    owner_exec, setuid = _OWNER_GROUP_EXEC_MAP[owner_exec_char]
    group_exec, setgid = _OWNER_GROUP_EXEC_MAP[group_exec_char]
    other_exec, sticky = _OTHER_EXEC_MAP[other_exec_char]

    owner_perms = f"{owner_rwx[0]}{owner_rwx[1]}{'x' if owner_exec else '-'}"
    group_perms = f"{group_rwx[0]}{group_rwx[1]}{'x' if group_exec else '-'}"
    other_perms = f"{other_rwx[0]}{other_rwx[1]}{'x' if other_exec else '-'}"

    numeric = format_octal_mode(
        owner_perms, group_perms, other_perms, setuid=setuid, setgid=setgid, sticky=sticky
    )

    return PermissionAnalysis(
        raw_text=perm_string,
        file_type=file_type,
        owner_perms=owner_perms,
        group_perms=group_perms,
        other_perms=other_perms,
        numeric=numeric,
        setuid=setuid,
        setgid=setgid,
        sticky=sticky,
        world_writable=other_perms[1] == "w",
    )


def parse_ls_line(line: str) -> PermissionAnalysis:
    """Parses a full `ls -l` line (permission string plus link count,
    owner, group, size, date, filename) into a `PermissionAnalysis` with
    `owner`/`group`/`filename` populated where present. Delegates the
    permission-string portion to `parse_ls_permission_string` — raises the
    same `InvalidPermissionStringError` if that portion is malformed."""
    stripped = line.strip()
    if not stripped:
        raise InvalidPermissionStringError("Empty ls -l line.")
    parts = stripped.split(None, 8)
    perm_string = parts[0]
    analysis = parse_ls_permission_string(perm_string)

    owner = parts[2] if len(parts) > 2 else None
    group = parts[3] if len(parts) > 3 else None
    filename = parts[8] if len(parts) > 8 else None

    return analysis.model_copy(update={"owner": owner, "group": group, "filename": filename})


def apply_symbolic_mode(base_octal: str, symbolic: str) -> str:
    """Applies a `chmod`-style symbolic mode string (`u+x`, `go-w`, `a=r`,
    `o+w`, comma-separated clauses allowed) against `base_octal` (a 3- or
    4-digit octal mode) and returns the resulting octal mode string.
    Raises `InvalidSymbolicModeError` for an unrecognized operator/target,
    and `InvalidOctalModeError` (propagated from `parse_octal_mode`) if
    `base_octal` itself is malformed."""
    if not symbolic or not _SYMBOLIC_MODE_PATTERN.match(symbolic):
        raise InvalidSymbolicModeError(f"Invalid symbolic chmod mode: {symbolic!r}.")

    owner_rwx, group_rwx, other_rwx, setuid, setgid, sticky = parse_octal_mode(base_octal)
    perms: dict[str, set[str]] = {
        "u": set(c for c in owner_rwx if c != "-"),
        "g": set(c for c in group_rwx if c != "-"),
        "o": set(c for c in other_rwx if c != "-"),
    }

    for clause in symbolic.split(","):
        operator_match = re.search(r"[+\-=]", clause)
        if operator_match is None:
            raise InvalidSymbolicModeError(f"Invalid symbolic chmod clause: {clause!r}.")
        operator_index = operator_match.start()
        targets = clause[:operator_index] or "a"
        operator = clause[operator_index]
        modes = set(clause[operator_index + 1 :])
        # 'X' (conditional execute) is treated as plain 'x' here — this
        # package never inspects an actual filesystem to know whether the
        # target already has any execute bit set, so it degrades to the
        # simpler, documented behavior rather than guessing.
        modes = {"x" if m == "X" else m for m in modes if m in "rwxXst"}

        expanded_targets = "ugo" if targets == "a" else targets
        for target in expanded_targets:
            if target not in perms:
                raise InvalidSymbolicModeError(f"Invalid symbolic chmod target: {target!r}.")
            if operator == "+":
                perms[target] |= modes - {"s", "t"}
            elif operator == "-":
                perms[target] -= modes
            elif operator == "=":
                perms[target] = modes - {"s", "t"}

        if "s" in modes and operator in "+=":
            if "u" in expanded_targets:
                setuid = True
            if "g" in expanded_targets:
                setgid = True
        if "t" in modes and operator in "+=":
            sticky = True

    def _triplet(bits: set[str]) -> str:
        r = "r" if "r" in bits else "-"
        w = "w" if "w" in bits else "-"
        x = "x" if "x" in bits else "-"
        return f"{r}{w}{x}"

    return format_octal_mode(
        _triplet(perms["u"]),
        _triplet(perms["g"]),
        _triplet(perms["o"]),
        setuid=setuid,
        setgid=setgid,
        sticky=sticky,
    )


def interpret_umask(umask: str) -> dict[str, str]:
    """Interprets a umask value (e.g. '022', '0027') as the resulting
    default permissions for newly-created files (base 666) and directories
    (base 777). Raises `InvalidUmaskError` on a malformed umask."""
    if not umask or not umask.isdigit() or len(umask) not in (3, 4):
        raise InvalidUmaskError(f"umask must be 3 or 4 octal digits, got {umask!r}.")
    if any(ch not in "01234567" for ch in umask):
        raise InvalidUmaskError(f"umask contains a non-octal digit: {umask!r}.")

    mask_digits = [int(d) for d in umask[-3:]]

    def _apply(base_digit: int, mask_digit: int) -> int:
        return base_digit & ~mask_digit & 0o7

    file_digits = [_apply(6, mask_digits[0]), _apply(6, mask_digits[1]), _apply(6, mask_digits[2])]
    dir_digits = [_apply(7, mask_digits[0]), _apply(7, mask_digits[1]), _apply(7, mask_digits[2])]

    default_file_mode = "".join(str(d) for d in file_digits)
    default_dir_mode = "".join(str(d) for d in dir_digits)
    return {"default_file_mode": default_file_mode, "default_dir_mode": default_dir_mode}
