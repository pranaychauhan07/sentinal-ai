"""`IOCNormalizer` — canonicalizes an already-*validated* `IOCRecord.value`
into the one comparable form `core.threat_intel.dedup.deduplicate_iocs` and
persistence rely on (constitution §1.9: deterministic, pure functions, no
LLM judgment involved in canonicalization).
"""

from __future__ import annotations

import ipaddress

from core.threat_intel.models import IOCRecord, IOCType


def _normalize_ipv4(value: str) -> str:
    return str(ipaddress.ip_address(value))


def _normalize_ipv6(value: str) -> str:
    return str(ipaddress.ip_address(value))


def _normalize_domain(value: str) -> str:
    return value.strip().rstrip(".").lower()


def _normalize_hostname(value: str) -> str:
    return value.strip().lower()


def _normalize_url(value: str) -> str:
    return value.strip()


def _normalize_email(value: str) -> str:
    return value.strip().lower()


def _normalize_hash(value: str) -> str:
    return value.strip().lower()


def _normalize_file_name(value: str) -> str:
    return value.strip()


def _normalize_username(value: str) -> str:
    return value.strip().lower()


def _normalize_process_name(value: str) -> str:
    return value.strip().lower()


def _normalize_registry_key(value: str) -> str:
    return value.strip().upper()


def _normalize_port(value: str) -> str:
    return str(int(value.strip()))


def _normalize_service(value: str) -> str:
    return value.strip().lower()


def _normalize_mutex(value: str) -> str:
    return value.strip()


def _normalize_scheduled_task(value: str) -> str:
    return value.strip()


def _normalize_command_line(value: str) -> str:
    return " ".join(value.strip().split())


def _normalize_user_agent(value: str) -> str:
    return value.strip()


def _normalize_certificate_fingerprint(value: str) -> str:
    return value.strip().upper().replace("-", ":")


_NORMALIZERS = {
    IOCType.IPV4: _normalize_ipv4,
    IOCType.IPV6: _normalize_ipv6,
    IOCType.DOMAIN: _normalize_domain,
    IOCType.HOSTNAME: _normalize_hostname,
    IOCType.URL: _normalize_url,
    IOCType.EMAIL: _normalize_email,
    IOCType.SHA1: _normalize_hash,
    IOCType.SHA256: _normalize_hash,
    IOCType.MD5: _normalize_hash,
    IOCType.FILE_NAME: _normalize_file_name,
    IOCType.USERNAME: _normalize_username,
    IOCType.PROCESS_NAME: _normalize_process_name,
    IOCType.REGISTRY_KEY: _normalize_registry_key,
    IOCType.PORT: _normalize_port,
    IOCType.SERVICE: _normalize_service,
    IOCType.MUTEX: _normalize_mutex,
    IOCType.SCHEDULED_TASK: _normalize_scheduled_task,
    IOCType.COMMAND_LINE: _normalize_command_line,
    IOCType.USER_AGENT: _normalize_user_agent,
    IOCType.CERTIFICATE_FINGERPRINT: _normalize_certificate_fingerprint,
}


class IOCNormalizer:
    """Stateless, deterministic per-type canonicalization. Assumes `ioc` has
    already passed `core.threat_intel.validator.IOCValidator` — normalizers
    do not re-validate structure, only canonicalize a known-well-formed
    value."""

    def normalize(self, ioc: IOCRecord) -> IOCRecord:
        """Return a new `IOCRecord` with `value` canonicalized. `raw_value`
        is preserved unchanged (constitution §1.7: never lose the original
        as observed)."""
        normalize_fn = _NORMALIZERS[ioc.ioc_type]
        canonical_value = normalize_fn(ioc.value)
        if canonical_value == ioc.value:
            return ioc
        return ioc.model_copy(update={"value": canonical_value})
