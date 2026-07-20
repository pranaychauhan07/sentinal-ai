"""`VulnerabilityNormalizer` — canonicalizes an already-*validated*
`VulnerabilityRecord` into the one comparable form
`core.vulnerabilities.dedup`/`asset_correlation`/persistence rely on
(constitution §1.9: deterministic, pure functions, no LLM judgment involved
in canonicalization). Mirrors `core.threat_intel.normalizer.IOCNormalizer`.
"""

from __future__ import annotations

from core.vulnerabilities.models import VulnerabilityRecord


def derive_asset_id(*, host: str | None, ip_address: str | None) -> str | None:
    """Deterministic asset identity key (task requirement: "Asset ID").
    Prefers the IP address (stable across DNS-name changes); falls back to
    host name; `None` if neither is present (an asset this framework cannot
    identify at all — a documented limitation, not silently invented)."""
    if ip_address:
        return ip_address.strip().lower()
    if host:
        return host.strip().lower()
    return None


class VulnerabilityNormalizer:
    """Stateless, deterministic canonicalization. Assumes `record` has
    already passed `core.vulnerabilities.validator.VulnerabilityValidator`."""

    def normalize(self, record: VulnerabilityRecord) -> VulnerabilityRecord:
        """Returns a new `VulnerabilityRecord` with `cve_id` upper-cased,
        `host`/`ip_address`/`service`/`protocol` lower-cased, and `asset_id`
        derived if not already set. `cve_id`/`cwe_ids` order is preserved
        (never re-sorted — first-seen order is meaningful provenance)."""
        canonical_host = record.host.strip().lower() if record.host is not None else None
        canonical_ip = record.ip_address.strip() if record.ip_address is not None else None

        updates: dict[str, object] = {}

        if record.cve_id is not None:
            canonical_cve = record.cve_id.strip().upper()
            if canonical_cve != record.cve_id:
                updates["cve_id"] = canonical_cve

        if record.cwe_ids:
            canonical_cwe_ids = tuple(dict.fromkeys(cwe.strip().upper() for cwe in record.cwe_ids))
            if canonical_cwe_ids != record.cwe_ids:
                updates["cwe_ids"] = canonical_cwe_ids

        if canonical_host != record.host:
            updates["host"] = canonical_host

        if canonical_ip != record.ip_address:
            updates["ip_address"] = canonical_ip

        if record.service is not None:
            canonical_service = record.service.strip().lower()
            if canonical_service != record.service:
                updates["service"] = canonical_service

        if record.protocol is not None:
            canonical_protocol = record.protocol.strip().lower()
            if canonical_protocol != record.protocol:
                updates["protocol"] = canonical_protocol

        if record.asset_id is None:
            derived = derive_asset_id(host=canonical_host, ip_address=canonical_ip)
            if derived is not None:
                updates["asset_id"] = derived

        if not updates:
            return record
        return record.model_copy(update=updates)
