"""`LinuxSecurityFindingGenerator` — groups already-scored
`ScoredLinuxSecurityCandidate` entries sharing the same `(category, subject)`
key into one `LinuxSecurityFinding` — a case-level aggregation, not a
per-line repeat of the same underlying detection. Deterministic grouping
only; no remediation text, no LLM reasoning (constitution §1.9, and the
task's explicit "do NOT implement Incident Response or remediation"
boundary).
"""

from __future__ import annotations

from core.linux_security.models import (
    LinuxSecurityFinding,
    ScoredLinuxSecurityCandidate,
)

_SEVERITY_ORDER: tuple[str, ...] = ("info", "low", "medium", "high", "critical")


def _finding_key(scored: ScoredLinuxSecurityCandidate) -> tuple[str, str]:
    return (scored.candidate.category.value, scored.candidate.subject)


class LinuxSecurityFindingGenerator:
    """Stateless, deterministic aggregation. One instance is safe to share
    across a whole pipeline run."""

    def generate(
        self, scored_candidates: list[ScoredLinuxSecurityCandidate]
    ) -> list[LinuxSecurityFinding]:
        groups: dict[tuple[str, str], list[ScoredLinuxSecurityCandidate]] = {}
        order: list[tuple[str, str]] = []
        for scored in scored_candidates:
            key = _finding_key(scored)
            if key not in groups:
                groups[key] = []
                order.append(key)
            groups[key].append(scored)

        findings: list[LinuxSecurityFinding] = []
        for key in order:
            group = groups[key]
            first = group[0].candidate
            highest_severity = max(
                (s.candidate.severity for s in group), key=lambda sev: _SEVERITY_ORDER.index(sev)
            )
            highest_score = max(s.score.composite_score for s in group)
            total_occurrences = sum(s.occurrence_count for s in group)
            line_numbers = tuple(
                dict.fromkeys(ln for s in group for ln in s.candidate.line_numbers)
            )
            evidence_ids = tuple(
                dict.fromkeys(
                    s.candidate.evidence_id for s in group if s.candidate.evidence_id is not None
                )
            )
            first_seen = min(s.candidate.first_seen for s in group)
            last_seen = max(s.candidate.last_seen for s in group)

            findings.append(
                LinuxSecurityFinding(
                    category=first.category,
                    subject=first.subject,
                    subject_type=first.subject_type,
                    title=first.title,
                    description=first.description,
                    severity=highest_severity,
                    composite_score=highest_score,
                    occurrence_count=total_occurrences,
                    line_numbers=line_numbers,
                    evidence_ids=evidence_ids,
                    first_seen=first_seen,
                    last_seen=last_seen,
                )
            )
        return findings
