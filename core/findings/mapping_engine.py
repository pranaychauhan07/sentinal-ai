"""`MitreMappingEngine` — the one concrete, rule-dispatching mapper
(`core/findings/mapping_rules.py`'s data table), not twenty near-duplicate
per-technique classes, matching `core/threat_intel/extractor.py`'s
precedent exactly (ADR-0012's central design decision, reapplied here per
ADR-0013).

Deterministic only (constitution §1.9): every confidence value is a plain
arithmetic combination of `MappingConfidenceFactors`, never an LLM guess. A
candidate `ScoredIOC` set that matches no rule, or whose best mapping falls
below `Settings.finding_mapping_min_confidence`, is simply left unmapped —
never forced into a low-confidence guess (blueprint §7's MITRE Agent
"Failure handling" behavior, restated here as the deterministic engine's own
contract).
"""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING

from core.findings.base import BaseFindingGenerator
from core.findings.exceptions import InvalidMappingRuleError
from core.findings.mapping_rules import MAPPING_RULES, MappingRule
from core.findings.models import MappingConfidenceFactors, MitreMapping
from core.knowledge.mitre.lookup import MitreLookup
from core.threat_intel.models import IOCType, ScoredIOC

if TYPE_CHECKING:
    from core.findings.metrics import FindingsMetricsCollector


class MitreMappingEngine(BaseFindingGenerator):
    """Maps a case's `ScoredIOC`s to ATT&CK techniques using
    `core/findings/mapping_rules.py`'s data table plus co-occurrence
    boosting, resolving each technique's tactic phases via `MitreLookup`."""

    name = "mitre_mapping_engine"
    description = "Rule-based, deterministic IOC-to-ATT&CK-technique mapper."

    def __init__(
        self,
        *,
        lookup: MitreLookup,
        rules: tuple[MappingRule, ...] = MAPPING_RULES,
        min_confidence: float = 0.0,
        metrics: FindingsMetricsCollector | None = None,
    ) -> None:
        super().__init__(metrics=metrics)
        for rule in rules:
            if not lookup.has_technique(rule.technique_id):
                raise InvalidMappingRuleError(
                    f"MappingRule {rule.rule_id!r} references technique "
                    f"{rule.technique_id!r}, which is absent from the loaded "
                    f"MitreDataset (attack_spec_version="
                    f"{lookup.dataset.attack_spec_version!r}).",
                    details={"rule_id": rule.rule_id, "technique_id": rule.technique_id},
                )
        self._lookup = lookup
        self._rules = rules
        self._min_confidence = min_confidence

    def map_candidates(self, iocs: list[ScoredIOC]) -> list[MitreMapping]:
        present_types: set[IOCType] = {ioc.record.ioc_type for ioc in iocs}

        # technique_id -> (matching ScoredIOCs, contributing rule confidences)
        by_technique: dict[str, list[ScoredIOC]] = defaultdict(list)
        rule_confidence_by_technique: dict[str, float] = {}

        for rule in self._rules:
            matches = [ioc for ioc in iocs if self._rule_matches_ioc(rule, ioc)]
            if not matches:
                continue
            co_occurs = bool(set(rule.co_occurrence_ioc_types) & present_types)
            rule_confidence = min(
                1.0, rule.base_confidence + (rule.co_occurrence_boost if co_occurs else 0.0)
            )
            existing = rule_confidence_by_technique.get(rule.technique_id, 0.0)
            rule_confidence_by_technique[rule.technique_id] = max(existing, rule_confidence)
            for match in matches:
                if match not in by_technique[rule.technique_id]:
                    by_technique[rule.technique_id].append(match)

        mappings: list[MitreMapping] = []
        for technique_id, matched_iocs in by_technique.items():
            rule_strength = rule_confidence_by_technique[technique_id]
            ioc_confidence = sum(ioc.record.confidence for ioc in matched_iocs) / len(matched_iocs)
            evidence_quality = sum(ioc.score.evidence_quality for ioc in matched_iocs) / len(
                matched_iocs
            )
            factors = MappingConfidenceFactors(
                rule_strength=rule_strength,
                ioc_confidence=ioc_confidence,
                evidence_quality=evidence_quality,
                supporting_indicator_count=len(matched_iocs),
            )
            confidence = self._compute_confidence(factors)
            if confidence < self._min_confidence:
                continue
            tactic_ids = tuple(
                tactic.tactic_id for tactic in self._lookup.tactics_for_technique(technique_id)
            )
            mappings.append(
                MitreMapping(
                    technique_id=technique_id,
                    tactic_ids=tactic_ids,
                    confidence=confidence,
                    mapping_source="rule_based",
                    attack_spec_version=self._lookup.dataset.attack_spec_version,
                    supporting_ioc_ids=tuple(ioc.record.ioc_id for ioc in matched_iocs),
                    factors=factors,
                )
            )

        mappings.sort(key=lambda mapping: mapping.confidence, reverse=True)
        return mappings

    @staticmethod
    def _rule_matches_ioc(rule: MappingRule, ioc: ScoredIOC) -> bool:
        if ioc.record.ioc_type not in rule.ioc_types:
            return False
        return not rule.match_tags or bool(set(rule.match_tags) & set(ioc.record.tags))

    @staticmethod
    def _compute_confidence(factors: MappingConfidenceFactors) -> float:
        """Deterministic combination — rule strength carries the most
        weight (it encodes the mapping's inherent precision), IOC/evidence
        quality moderate it, and additional supporting indicators saturate
        a small bonus rather than dominate the score."""
        supporting_bonus = min(0.15, 0.05 * max(0, factors.supporting_indicator_count - 1))
        combined = (
            0.5 * factors.rule_strength
            + 0.25 * factors.ioc_confidence
            + 0.15 * factors.evidence_quality
            + supporting_bonus
        )
        return max(0.0, min(1.0, combined))
