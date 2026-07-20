"""Vulnerability deduplication — collapses repeated observations of the same
underlying vulnerability within one extraction run into a single
`VulnerabilityRecord`, never dropping provenance (constitution §1.7): the
earliest `first_seen` wins, the highest observed `confidence` is kept, and
`occurrence_count` tracks how many raw candidates merged into the result.

Configurable dedup key (task requirement: "same asset / same CVE / same
plugin / same service / same port") — the default composite key
(`ASSET_AND_CVE`) is the most common real-world dedup boundary (the same
CVE reported once per host is one finding, not N), but a caller may select
any strategy, or compose its own via `DedupStrategy.CUSTOM` +
`key_fn`.
"""

from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum

from core.vulnerabilities.models import VulnerabilityRecord

DedupKey = tuple[object, ...]


class DedupStrategy(StrEnum):
    """Closed set of built-in dedup key strategies this engine supports."""

    ASSET_AND_CVE = "asset_and_cve"
    ASSET_AND_PLUGIN = "asset_and_plugin"
    SAME_SERVICE = "same_service"
    SAME_PORT = "same_port"
    CUSTOM = "custom"


def _key_asset_and_cve(record: VulnerabilityRecord) -> DedupKey:
    return (record.asset_id, record.cve_id or record.plugin_id)


def _key_asset_and_plugin(record: VulnerabilityRecord) -> DedupKey:
    return (record.asset_id, record.plugin_id or record.cve_id)


def _key_same_service(record: VulnerabilityRecord) -> DedupKey:
    return (record.asset_id, record.service, record.cve_id or record.plugin_id)


def _key_same_port(record: VulnerabilityRecord) -> DedupKey:
    return (record.asset_id, record.port, record.cve_id or record.plugin_id)


_BUILTIN_KEY_FUNCTIONS: dict[DedupStrategy, Callable[[VulnerabilityRecord], DedupKey]] = {
    DedupStrategy.ASSET_AND_CVE: _key_asset_and_cve,
    DedupStrategy.ASSET_AND_PLUGIN: _key_asset_and_plugin,
    DedupStrategy.SAME_SERVICE: _key_same_service,
    DedupStrategy.SAME_PORT: _key_same_port,
}


class VulnerabilityDeduplicationEngine:
    """Configurable, deterministic deduplication over one extraction run's
    candidate set — scoped to *within* one run, mirroring
    `core.threat_intel.dedup.deduplicate_iocs`'s identical scope cut (not
    cross-case/cross-evidence correlation)."""

    def __init__(
        self,
        *,
        strategy: DedupStrategy = DedupStrategy.ASSET_AND_CVE,
        key_fn: Callable[[VulnerabilityRecord], DedupKey] | None = None,
    ) -> None:
        if strategy is DedupStrategy.CUSTOM and key_fn is None:
            raise ValueError("DedupStrategy.CUSTOM requires an explicit key_fn.")
        self._strategy = strategy
        self._key_fn = key_fn or _BUILTIN_KEY_FUNCTIONS.get(strategy, _key_asset_and_cve)

    def deduplicate(
        self, candidates: list[VulnerabilityRecord]
    ) -> list[tuple[VulnerabilityRecord, int]]:
        """Merge candidates sharing the same dedup key. Returns
        `(merged_record, occurrence_count)` pairs in first-appearance order
        — `occurrence_count` is exposed explicitly here (rather than folded
        into `VulnerabilityRecord` itself) since it is a property of *this
        run's* observations, not of the vulnerability itself."""
        merged: dict[DedupKey, VulnerabilityRecord] = {}
        counts: dict[DedupKey, int] = {}
        order: list[DedupKey] = []

        for candidate in candidates:
            key = self._key_fn(candidate)
            existing = merged.get(key)
            if existing is None:
                merged[key] = candidate
                counts[key] = 1
                order.append(key)
                continue
            merged[key] = _merge(existing, candidate)
            counts[key] += 1

        return [(merged[key], counts[key]) for key in order]


def _merge(existing: VulnerabilityRecord, incoming: VulnerabilityRecord) -> VulnerabilityRecord:
    merged_tags = tuple(dict.fromkeys((*existing.tags, *incoming.tags)))
    line_numbers_context = list(existing.context.get("line_numbers", []))
    if existing.line_number is not None and existing.line_number not in line_numbers_context:
        line_numbers_context.append(existing.line_number)
    if incoming.line_number is not None and incoming.line_number not in line_numbers_context:
        line_numbers_context.append(incoming.line_number)

    merged_references = tuple(dict.fromkeys((*existing.references, *incoming.references)))
    merged_cwe_ids = tuple(dict.fromkeys((*existing.cwe_ids, *incoming.cwe_ids)))

    return existing.model_copy(
        update={
            "confidence": max(existing.confidence, incoming.confidence),
            "first_seen": min(existing.first_seen, incoming.first_seen),
            "tags": merged_tags,
            "references": merged_references,
            "cwe_ids": merged_cwe_ids,
            "context": {**existing.context, "line_numbers": line_numbers_context},
        }
    )
