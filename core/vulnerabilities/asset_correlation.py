"""Asset Correlation — deterministic grouping of `VulnerabilityRecord`s that
affect the same asset (task requirement: "Asset Correlation"), so a case
view can answer "what does this host have wrong with it" as directly as
"what hosts have this CVE." Pure aggregation; no LLM judgment.
"""

from __future__ import annotations

from core.vulnerabilities.models import AssetCorrelation, VulnerabilityRecord, VulnerabilitySeverity

_SEVERITY_ORDER: tuple[VulnerabilitySeverity, ...] = (
    VulnerabilitySeverity.INFO,
    VulnerabilitySeverity.LOW,
    VulnerabilitySeverity.MEDIUM,
    VulnerabilitySeverity.HIGH,
    VulnerabilitySeverity.CRITICAL,
)


def correlate_by_asset(records: list[VulnerabilityRecord]) -> list[AssetCorrelation]:
    """Groups `records` by `asset_id`, in first-appearance order. A record
    with no `asset_id` (host/IP could not be identified) is excluded from
    every correlation — it is still scored/persisted individually, just not
    grouped, matching `core.vulnerabilities.normalizer.derive_asset_id`'s
    documented "cannot identify" limitation."""
    grouped: dict[str, list[VulnerabilityRecord]] = {}
    order: list[str] = []

    for record in records:
        if record.asset_id is None:
            continue
        if record.asset_id not in grouped:
            grouped[record.asset_id] = []
            order.append(record.asset_id)
        grouped[record.asset_id].append(record)

    correlations: list[AssetCorrelation] = []
    for asset_id in order:
        group = grouped[asset_id]
        highest = max((r.severity for r in group), key=_SEVERITY_ORDER.index)
        correlations.append(
            AssetCorrelation(
                asset_id=asset_id,
                host=next((r.host for r in group if r.host), None),
                ip_address=next((r.ip_address for r in group if r.ip_address), None),
                vuln_ids=tuple(r.vuln_id for r in group),
                highest_severity=highest,
            )
        )
    return correlations
