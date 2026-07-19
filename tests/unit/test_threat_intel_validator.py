"""Unit tests for core/threat_intel/validator.py — IOCValidator."""

from __future__ import annotations

import pytest

from core.threat_intel.exceptions import IOCValidationError
from core.threat_intel.models import IOCRecord, IOCType
from core.threat_intel.validator import IOCValidator


def _ioc(ioc_type: IOCType, value: str) -> IOCRecord:
    return IOCRecord(ioc_type=ioc_type, value=value, raw_value=value, source="test")


@pytest.mark.unit
@pytest.mark.parametrize(
    ("ioc_type", "value"),
    [
        (IOCType.IPV4, "192.168.1.1"),
        (IOCType.IPV6, "2001:db8::1"),
        (IOCType.DOMAIN, "example.com"),
        (IOCType.HOSTNAME, "web-server-01"),
        (IOCType.URL, "https://example.com/path"),
        (IOCType.EMAIL, "user@example.com"),
        (IOCType.SHA1, "a" * 40),
        (IOCType.SHA256, "b" * 64),
        (IOCType.MD5, "c" * 32),
        (IOCType.FILE_NAME, "malware.exe"),
        (IOCType.USERNAME, "jdoe"),
        (IOCType.PROCESS_NAME, "powershell.exe"),
        (IOCType.REGISTRY_KEY, "HKLM\\Software\\Evil"),
        (IOCType.PORT, "8080"),
        (IOCType.SERVICE, "sshd"),
        (IOCType.MUTEX, "Global\\SomeMutex"),
        (IOCType.SCHEDULED_TASK, "\\Microsoft\\Windows\\Task"),
        (IOCType.COMMAND_LINE, "cmd.exe /c whoami"),
        (IOCType.USER_AGENT, "Mozilla/5.0 (Windows NT 10.0)"),
        (IOCType.CERTIFICATE_FINGERPRINT, ("AB:" * 19) + "CD"),
    ],
)
def test_valid_iocs_pass_validation(ioc_type: IOCType, value: str) -> None:
    validator = IOCValidator()
    validator.validate(_ioc(ioc_type, value))  # must not raise


@pytest.mark.unit
@pytest.mark.parametrize(
    ("ioc_type", "value"),
    [
        (IOCType.IPV4, "999.999.999.999"),
        (IOCType.IPV6, "not-an-ipv6"),
        (IOCType.DOMAIN, "-invalid-.com"),
        (IOCType.URL, "not a url"),
        (IOCType.EMAIL, "not-an-email"),
        (IOCType.SHA1, "tooshort"),
        (IOCType.SHA256, "z" * 64),
        (IOCType.MD5, "a" * 31),
        (IOCType.PORT, "99999"),
        (IOCType.PORT, "not-a-number"),
        (IOCType.REGISTRY_KEY, "NotARegistryKey"),
        (IOCType.CERTIFICATE_FINGERPRINT, "short"),
    ],
)
def test_invalid_iocs_fail_validation(ioc_type: IOCType, value: str) -> None:
    validator = IOCValidator()
    with pytest.raises(IOCValidationError):
        validator.validate(_ioc(ioc_type, value))


@pytest.mark.unit
def test_is_valid_returns_false_without_raising() -> None:
    validator = IOCValidator()
    assert validator.is_valid(_ioc(IOCType.IPV4, "not-an-ip")) is False
    assert validator.is_valid(_ioc(IOCType.IPV4, "1.2.3.4")) is True
