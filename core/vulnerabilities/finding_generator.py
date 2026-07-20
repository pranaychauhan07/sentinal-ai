"""`VulnerabilityFindingGenerator` — the Finding Generation pipeline stage
(task requirement). Groups already-deduplicated, already-scored
`ScoredVulnerability` entries sharing the same CVE (or, absent a CVE, the
same plugin) across however many assets into one `VulnerabilityFinding` —
a case-level aggregation, not a per-host repeat of the same underlying
issue. Deterministic grouping only; no remediation text, no LLM reasoning
(constitution §1.9, and the task's explicit "do NOT implement remediation
planning" boundary).
"""

from __future__ import annotations

from core.vulnerabilities.models import (
    ScoredVulnerability,
    VulnerabilityFinding,
    VulnerabilityPriority,
)
from core.vulnerabilities.severity import SEVERITY_ORDER

_PRIORITY_ORDER: tuple[VulnerabilityPriority, ...] = (
    VulnerabilityPriority.P4_LOW,
    VulnerabilityPriority.P3_MEDIUM,
    VulnerabilityPriority.P2_HIGH,
    VulnerabilityPriority.P1_CRITICAL,
)


def _finding_key(scored: ScoredVulnerability) -> str:
    record = scored.record
    return record.cve_id or record.plugin_id or record.plugin_name


class VulnerabilityFindingGenerator:
    """Stateless, deterministic aggregation. One instance is safe to share
    across a whole pipeline run."""

    def generate(
        self, scored_vulnerabilities: list[ScoredVulnerability]
    ) -> list[VulnerabilityFinding]:
        """Groups by `_finding_key` in first-appearance order. Every group's
        finding takes the *highest* severity/priority/composite score among
        its members (the most severe observation drives triage), and the
        union of affected assets/references."""
        groups: dict[str, list[ScoredVulnerability]] = {}
        order: list[str] = []
        for scored in scored_vulnerabilities:
            key = _finding_key(scored)
            if key not in groups:
                groups[key] = []
                order.append(key)
            groups[key].append(scored)

        findings: list[VulnerabilityFinding] = []
        for key in order:
            group = groups[key]
            first_record = group[0].record
            highest_severity = max((s.record.severity for s in group), key=SEVERITY_ORDER.index)
            highest_priority = max((s.priority for s in group), key=_PRIORITY_ORDER.index)
            highest_score = max(s.score.composite_score for s in group)
            affected_asset_ids = tuple(
                dict.fromkeys(s.record.asset_id for s in group if s.record.asset_id is not None)
            )
            references = tuple(dict.fromkeys(ref for s in group for ref in s.record.references))
            title = (
                f"{first_record.cve_id} — {first_record.plugin_name}"
                if first_record.cve_id
                else first_record.plugin_name or f"Plugin {first_record.plugin_id}"
            )

            findings.append(
                VulnerabilityFinding(
                    cve_id=first_record.cve_id,
                    plugin_id=first_record.plugin_id,
                    title=title,
                    description=first_record.description,
                    severity=highest_severity,
                    priority=highest_priority,
                    composite_score=highest_score,
                    affected_asset_ids=affected_asset_ids,
                    vuln_ids=tuple(s.record.vuln_id for s in group),
                    references=references,
                )
            )
        return findings
