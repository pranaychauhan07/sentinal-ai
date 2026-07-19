"""`IOCValidator` — the format-correctness gate every candidate `IOCRecord`
crosses before normalization (constitution §10, "input validation ... at
the boundary"), mirroring `core/parsers/validation.py`'s role for uploads.

Deliberately independent of extraction: a candidate produced by *any*
extractor (the built-in `IOCExtractionEngine` or a future plugin) is
validated the same way, by type.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from core.threat_intel.exceptions import IOCValidationError
from core.threat_intel.models import IOCRecord, IOCType

_HASH_LENGTHS: dict[IOCType, int] = {
    IOCType.MD5: 32,
    IOCType.SHA1: 40,
    IOCType.SHA256: 64,
}
_HEX_RE = re.compile(r"^[A-Fa-f0-9]+$")
_DOMAIN_RE = re.compile(
    r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){1,10}[A-Za-z]{2,24}$"
)
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}$")
_REGISTRY_ROOTS = ("HKEY_", "HKLM", "HKCU", "HKCR", "HKU", "HKCC")


def _fail(ioc: IOCRecord, reason: str) -> None:
    raise IOCValidationError(
        f"IOC value {ioc.raw_value!r} failed {ioc.ioc_type.value} validation: {reason}",
        details={"ioc_type": ioc.ioc_type.value, "value": ioc.raw_value, "reason": reason},
    )


def _validate_ipv4(ioc: IOCRecord) -> None:
    try:
        address = ipaddress.ip_address(ioc.value)
    except ValueError:
        _fail(ioc, "not a valid IP address")
        return
    if not isinstance(address, ipaddress.IPv4Address):
        _fail(ioc, "not an IPv4 address")


def _validate_ipv6(ioc: IOCRecord) -> None:
    try:
        address = ipaddress.ip_address(ioc.value)
    except ValueError:
        _fail(ioc, "not a valid IP address")
        return
    if not isinstance(address, ipaddress.IPv6Address):
        _fail(ioc, "not an IPv6 address")


def _validate_domain(ioc: IOCRecord) -> None:
    if len(ioc.value) > 253 or not _DOMAIN_RE.match(ioc.value):
        _fail(ioc, "not a well-formed domain name")


def _validate_hostname(ioc: IOCRecord) -> None:
    if len(ioc.value) > 253 or not _HOSTNAME_RE.match(ioc.value):
        _fail(ioc, "not a well-formed hostname")


def _validate_url(ioc: IOCRecord) -> None:
    parsed = urlparse(ioc.value)
    if not parsed.scheme or not parsed.netloc:
        _fail(ioc, "missing scheme or network location")


def _validate_email(ioc: IOCRecord) -> None:
    if not _EMAIL_RE.match(ioc.value):
        _fail(ioc, "not a well-formed email address")


def _validate_hash(ioc: IOCRecord) -> None:
    expected_length = _HASH_LENGTHS[ioc.ioc_type]
    if len(ioc.value) != expected_length or not _HEX_RE.match(ioc.value):
        _fail(ioc, f"expected {expected_length} hex characters")


def _validate_file_name(ioc: IOCRecord) -> None:
    if "." not in ioc.value or len(ioc.value) > 255:
        _fail(ioc, "not a well-formed file name")


def _validate_username(ioc: IOCRecord) -> None:
    if not ioc.value or len(ioc.value) > 64:
        _fail(ioc, "empty or excessively long username")


def _validate_process_name(ioc: IOCRecord) -> None:
    if not ioc.value or len(ioc.value) > 260:
        _fail(ioc, "empty or excessively long process name")


def _validate_registry_key(ioc: IOCRecord) -> None:
    if not ioc.value.startswith(_REGISTRY_ROOTS):
        _fail(ioc, "does not start with a known registry hive root")


def _validate_port(ioc: IOCRecord) -> None:
    try:
        port = int(ioc.value)
    except ValueError:
        _fail(ioc, "not an integer")
        return
    if not (1 <= port <= 65535):
        _fail(ioc, "outside the valid 1-65535 port range")


def _validate_service(ioc: IOCRecord) -> None:
    if not ioc.value or len(ioc.value) > 64:
        _fail(ioc, "empty or excessively long service name")


def _validate_mutex(ioc: IOCRecord) -> None:
    if not ioc.value or len(ioc.value) > 260:
        _fail(ioc, "empty or excessively long mutex name")


def _validate_scheduled_task(ioc: IOCRecord) -> None:
    if not ioc.value or len(ioc.value) > 260:
        _fail(ioc, "empty or excessively long scheduled task path")


def _validate_command_line(ioc: IOCRecord) -> None:
    if not ioc.value.strip():
        _fail(ioc, "empty command line")


def _validate_user_agent(ioc: IOCRecord) -> None:
    if not ioc.value.strip():
        _fail(ioc, "empty user agent string")


def _validate_certificate_fingerprint(ioc: IOCRecord) -> None:
    stripped = ioc.value.replace(":", "")
    if len(stripped) not in (40, 64) or not _HEX_RE.match(stripped):
        _fail(ioc, "not a well-formed SHA1/SHA256 certificate fingerprint")


_VALIDATORS = {
    IOCType.IPV4: _validate_ipv4,
    IOCType.IPV6: _validate_ipv6,
    IOCType.DOMAIN: _validate_domain,
    IOCType.HOSTNAME: _validate_hostname,
    IOCType.URL: _validate_url,
    IOCType.EMAIL: _validate_email,
    IOCType.SHA1: _validate_hash,
    IOCType.SHA256: _validate_hash,
    IOCType.MD5: _validate_hash,
    IOCType.FILE_NAME: _validate_file_name,
    IOCType.USERNAME: _validate_username,
    IOCType.PROCESS_NAME: _validate_process_name,
    IOCType.REGISTRY_KEY: _validate_registry_key,
    IOCType.PORT: _validate_port,
    IOCType.SERVICE: _validate_service,
    IOCType.MUTEX: _validate_mutex,
    IOCType.SCHEDULED_TASK: _validate_scheduled_task,
    IOCType.COMMAND_LINE: _validate_command_line,
    IOCType.USER_AGENT: _validate_user_agent,
    IOCType.CERTIFICATE_FINGERPRINT: _validate_certificate_fingerprint,
}


class IOCValidator:
    """Stateless, deterministic per-type validation. One instance is safe
    to share across a whole pipeline run (no internal mutable state)."""

    def validate(self, ioc: IOCRecord) -> None:
        """Raise `core.threat_intel.exceptions.IOCValidationError` if `ioc`
        fails its type-specific rule. Returns `None` on success — callers
        treat "did not raise" as the pass signal, matching
        `core.parsers.base.BaseParser.raise_if_invalid`'s convention."""
        validator = _VALIDATORS[ioc.ioc_type]
        validator(ioc)

    def is_valid(self, ioc: IOCRecord) -> bool:
        try:
            self.validate(ioc)
        except IOCValidationError:
            return False
        return True
