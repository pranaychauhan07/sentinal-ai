"""Unit tests for core/linux_advisor/permission_parser.py — pure
octal/rwx/`ls -l`/symbolic-mode/umask conversion functions, both directions,
plus malformed-input cases."""

from __future__ import annotations

import pytest

from core.linux_advisor.exceptions import (
    InvalidOctalModeError,
    InvalidPermissionStringError,
    InvalidSymbolicModeError,
    InvalidUmaskError,
)
from core.linux_advisor.permission_parser import (
    apply_symbolic_mode,
    format_octal_mode,
    interpret_umask,
    octal_digit_to_rwx,
    parse_ls_line,
    parse_ls_permission_string,
    parse_octal_mode,
    rwx_to_octal_digit,
)

pytestmark = pytest.mark.unit


# --- octal_digit_to_rwx / rwx_to_octal_digit (round trip) -------------------


@pytest.mark.parametrize("digit,expected", [(0, "---"), (7, "rwx"), (5, "r-x"), (2, "-w-")])
def test_octal_digit_to_rwx(digit: int, expected: str) -> None:
    assert octal_digit_to_rwx(digit) == expected


@pytest.mark.parametrize("digit", [-1, 8, 100])
def test_octal_digit_to_rwx_invalid(digit: int) -> None:
    with pytest.raises(InvalidOctalModeError):
        octal_digit_to_rwx(digit)


@pytest.mark.parametrize("digit", range(8))
def test_round_trip_octal_rwx(digit: int) -> None:
    assert rwx_to_octal_digit(octal_digit_to_rwx(digit)) == digit


def test_rwx_to_octal_digit_wrong_length() -> None:
    with pytest.raises(InvalidOctalModeError):
        rwx_to_octal_digit("rw")


def test_rwx_to_octal_digit_invalid_chars() -> None:
    with pytest.raises(InvalidOctalModeError):
        rwx_to_octal_digit("zzz")


# --- parse_octal_mode / format_octal_mode -----------------------------------


def test_parse_octal_mode_three_digit() -> None:
    owner, group, other, setuid, setgid, sticky = parse_octal_mode("755")
    assert (owner, group, other) == ("rwx", "r-x", "r-x")
    assert not setuid and not setgid and not sticky


def test_parse_octal_mode_four_digit_setuid() -> None:
    owner, group, other, setuid, setgid, sticky = parse_octal_mode("4755")
    assert setuid and not setgid and not sticky


def test_parse_octal_mode_sticky_bit() -> None:
    _, _, _, setuid, setgid, sticky = parse_octal_mode("1777")
    assert sticky and not setuid and not setgid


@pytest.mark.parametrize("mode", ["", "75", "75555", "abc", "789", "-1"])
def test_parse_octal_mode_malformed(mode: str) -> None:
    with pytest.raises(InvalidOctalModeError):
        parse_octal_mode(mode)


def test_format_octal_mode_round_trip() -> None:
    assert format_octal_mode("rwx", "r-x", "r-x") == "755"


def test_format_octal_mode_with_special_bits() -> None:
    assert format_octal_mode("rwx", "rwx", "rwx", setuid=True, sticky=True) == "5777"


def test_octal_mode_round_trip_full() -> None:
    for mode in ("755", "644", "4755", "2775", "1777"):
        owner, group, other, setuid, setgid, sticky = parse_octal_mode(mode)
        assert (
            format_octal_mode(owner, group, other, setuid=setuid, setgid=setgid, sticky=sticky)
            == mode
        )


# --- parse_ls_permission_string ---------------------------------------------


def test_parse_ls_permission_string_basic_file() -> None:
    analysis = parse_ls_permission_string("-rwxr-xr-x")
    assert analysis.file_type == "-"
    assert analysis.owner_perms == "rwx"
    assert analysis.group_perms == "r-x"
    assert analysis.other_perms == "r-x"
    assert analysis.numeric == "755"
    assert not analysis.world_writable


def test_parse_ls_permission_string_world_writable() -> None:
    analysis = parse_ls_permission_string("-rwxrwxrwx")
    assert analysis.world_writable


def test_parse_ls_permission_string_directory() -> None:
    analysis = parse_ls_permission_string("drwxr-xr-x")
    assert analysis.file_type == "d"


def test_parse_ls_permission_string_setuid() -> None:
    analysis = parse_ls_permission_string("-rwsr-xr-x")
    assert analysis.setuid
    assert analysis.owner_perms == "rwx"


def test_parse_ls_permission_string_setuid_no_exec() -> None:
    analysis = parse_ls_permission_string("-rwSr-xr-x")
    assert analysis.setuid
    assert analysis.owner_perms == "rw-"


def test_parse_ls_permission_string_sticky() -> None:
    analysis = parse_ls_permission_string("drwxrwxrwt")
    assert analysis.sticky
    assert analysis.other_perms == "rwx"


def test_parse_ls_permission_string_sticky_no_exec() -> None:
    analysis = parse_ls_permission_string("drwxrwxrwT")
    assert analysis.sticky
    assert analysis.other_perms == "rw-"


@pytest.mark.parametrize(
    "malformed",
    [
        "",
        "rwxr-xr-x",  # 9 chars, missing file type
        "-rwxr-xr-xx",  # 11 chars
        "zrwxr-xr-x",  # invalid file type char
        "-rwzr-xr-x",  # invalid read/write char
    ],
)
def test_parse_ls_permission_string_malformed(malformed: str) -> None:
    with pytest.raises(InvalidPermissionStringError):
        parse_ls_permission_string(malformed)


def test_parse_ls_line_extracts_owner_group_filename() -> None:
    analysis = parse_ls_line("-rw-r--r-- 1 root root 1234 Jan 1 00:00 /etc/shadow")
    assert analysis.owner == "root"
    assert analysis.group == "root"
    assert analysis.filename == "/etc/shadow"
    assert analysis.other_perms == "r--"


def test_parse_ls_line_empty_raises() -> None:
    with pytest.raises(InvalidPermissionStringError):
        parse_ls_line("   ")


# --- apply_symbolic_mode -----------------------------------------------------


def test_apply_symbolic_mode_add_execute() -> None:
    assert apply_symbolic_mode("644", "u+x") == "744"


def test_apply_symbolic_mode_remove_write_group_other() -> None:
    assert apply_symbolic_mode("777", "go-w") == "755"


def test_apply_symbolic_mode_set_all_read() -> None:
    assert apply_symbolic_mode("777", "a=r") == "444"


def test_apply_symbolic_mode_other_plus_write() -> None:
    assert apply_symbolic_mode("644", "o+w") == "646"


def test_apply_symbolic_mode_multiple_clauses() -> None:
    assert apply_symbolic_mode("644", "u+x,g+w") == "764"


@pytest.mark.parametrize("symbolic", ["", "u@x", "zzz", "u#x", "1+2"])
def test_apply_symbolic_mode_malformed(symbolic: str) -> None:
    with pytest.raises(InvalidSymbolicModeError):
        apply_symbolic_mode("644", symbolic)


def test_apply_symbolic_mode_invalid_base_octal_propagates() -> None:
    with pytest.raises(InvalidOctalModeError):
        apply_symbolic_mode("999", "u+x")


# --- interpret_umask ---------------------------------------------------------


def test_interpret_umask_022() -> None:
    result = interpret_umask("022")
    assert result == {"default_file_mode": "644", "default_dir_mode": "755"}


def test_interpret_umask_077() -> None:
    result = interpret_umask("077")
    assert result == {"default_file_mode": "600", "default_dir_mode": "700"}


def test_interpret_umask_four_digit() -> None:
    result = interpret_umask("0022")
    assert result == {"default_file_mode": "644", "default_dir_mode": "755"}


@pytest.mark.parametrize("umask", ["", "9", "888", "abc", "12"])
def test_interpret_umask_malformed(umask: str) -> None:
    with pytest.raises(InvalidUmaskError):
        interpret_umask(umask)
