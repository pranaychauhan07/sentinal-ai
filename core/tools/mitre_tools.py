"""`MitreMappingResolutionTool` — blueprint's exact named `mitre_tools.py`:
the MITRE Mapping Agent's deterministic technique/tactic/group/software/
mitigation resolution tool.

Never re-derives a technique-to-Finding mapping or its confidence itself —
that is entirely `core.findings.mapping_engine.MitreMappingEngine`'s job,
already run by `core.services.finding_service.generate_findings_for_case`
before this tool ever sees a case's data (constitution §1.9). This tool only
*resolves* reference metadata for already-mapped technique IDs: tactic
phases, sub-technique parents, associated threat groups, associated
software, and mitigations — all read from `core.knowledge.mitre.lookup.
MitreLookup`, never recomputed.

Unlike every other `core/tools/*.py` module (`vuln_tools.py`, `owasp_tools.py`,
...), this tool's constructor takes an injected `MitreLookup` dependency and
its input stays typed rather than dict-shaped: `core/tools` is explicitly
allowed to import `core/knowledge` directly (docs/dependency-rules.md rule
5) — `core.knowledge.mitre` is shared reference data, not a sibling leaf's
private model, so there is no "why input stays dict-shaped" boundary to
observe here (contrast `vuln_tools.py`'s docstring, which documents exactly
that boundary for `core.vulnerabilities`).
"""

from __future__ import annotations

from collections import defaultdict
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

from core.knowledge.mitre.lookup import MitreLookup
from core.tools.base import BaseTool

#: Default number of highest-confidence techniques surfaced in the summary.
DEFAULT_TOP_N = 10


def parent_technique_id(technique_id: str) -> str | None:
    """Returns the parent technique ID for a sub-technique (e.g.
    ``"T1110.001"`` -> ``"T1110"``), or ``None`` if `technique_id` is not
    sub-technique-shaped. ATT&CK's own ID convention (a literal ``"."``) is
    the only signal used — this package vendors no separate parent/child
    relationship data, and none is needed: the parent ID is always the
    substring before the first ``"."``."""
    if "." not in technique_id:
        return None
    return technique_id.split(".", 1)[0]


class MitreTechniqueMappingInput(BaseModel):
    """One already-computed technique mapping for a case's Finding — every
    field here is a value `core.findings.mapping_engine.MitreMappingEngine`
    already computed and persisted; this model performs no validation
    beyond typing (constitution §1.9: resolution, not judgment)."""

    model_config = ConfigDict(frozen=True)

    technique_id: str
    tactic_ids: tuple[str, ...] = ()
    confidence: float = 0.0
    mapping_source: str = ""
    finding_id: str = ""


class MitreCaseMappingInput(BaseModel):
    """A case's full set of already-computed technique mappings, across
    every Finding generated for it so far."""

    model_config = ConfigDict(frozen=True)

    mappings: list[MitreTechniqueMappingInput] = Field(default_factory=list)
    top_n: int = Field(default=DEFAULT_TOP_N, ge=1)


class MitreTechniqueResolution(BaseModel):
    """One technique's fully resolved ATT&CK metadata plus the case-specific
    mapping data that produced it."""

    model_config = ConfigDict(frozen=True)

    technique_id: str
    technique_name: str
    is_subtechnique: bool = False
    parent_technique_id: str | None = None
    tactic_ids: tuple[str, ...] = ()
    tactic_names: tuple[str, ...] = ()
    group_ids: tuple[str, ...] = ()
    group_names: tuple[str, ...] = ()
    software_ids: tuple[str, ...] = ()
    software_names: tuple[str, ...] = ()
    mitigation_ids: tuple[str, ...] = ()
    mitigation_names: tuple[str, ...] = ()
    confidence: float = Field(ge=0.0, le=1.0)
    supporting_finding_ids: tuple[str, ...] = ()


class MitreCaseMappingOutput(BaseModel):
    model_config = ConfigDict(frozen=True)

    technique_count: int = 0
    tactic_coverage: dict[str, int] = Field(default_factory=dict)
    distinct_group_count: int = 0
    distinct_software_count: int = 0
    resolved_techniques: tuple[MitreTechniqueResolution, ...] = ()
    unresolved_technique_ids: tuple[str, ...] = ()
    top_techniques: tuple[MitreTechniqueResolution, ...] = ()


class MitreMappingResolutionTool(BaseTool[MitreCaseMappingInput, MitreCaseMappingOutput]):
    """Deterministic, no-I/O — never retried (constitution §5/§4.8). Given
    the same input and the same loaded `MitreDataset`, always returns the
    same output. Gracefully degrades (`unresolved_technique_ids`) for a
    technique_id absent from the loaded dataset (a version mismatch, or a
    reference table that hasn't been re-seeded) rather than raising."""

    name: ClassVar[str] = "mitre_mapping_resolution"
    description: ClassVar[str] = (
        "Resolves already-computed technique mappings to their ATT&CK "
        "tactics, sub-technique parent, associated threat groups, "
        "associated software, and mitigations."
    )
    is_io_bound: ClassVar[bool] = False

    def __init__(self, *, lookup: MitreLookup) -> None:
        super().__init__()
        self._lookup = lookup

    def run(self, arguments: MitreCaseMappingInput) -> MitreCaseMappingOutput:
        by_technique: dict[str, list[MitreTechniqueMappingInput]] = defaultdict(list)
        for mapping in arguments.mappings:
            by_technique[mapping.technique_id].append(mapping)

        resolved: list[MitreTechniqueResolution] = []
        unresolved: list[str] = []
        tactic_coverage: dict[str, int] = {}
        all_group_ids: set[str] = set()
        all_software_ids: set[str] = set()

        for technique_id, matches in by_technique.items():
            if not self._lookup.has_technique(technique_id):
                unresolved.append(technique_id)
                continue

            technique = self._lookup.technique_by_id(technique_id)
            tactics = self._lookup.tactics_for_technique(technique_id)
            groups = self._lookup.groups_using_technique(technique_id)
            software = self._lookup.software_using_technique(technique_id)
            mitigations = self._lookup.mitigations_for_technique(technique_id)

            for tactic in tactics:
                tactic_coverage[tactic.tactic_id] = tactic_coverage.get(tactic.tactic_id, 0) + 1
            all_group_ids.update(group.group_id for group in groups)
            all_software_ids.update(item.software_id for item in software)

            parent_id = parent_technique_id(technique_id)
            resolved.append(
                MitreTechniqueResolution(
                    technique_id=technique_id,
                    technique_name=technique.name,
                    is_subtechnique=parent_id is not None,
                    parent_technique_id=parent_id,
                    tactic_ids=tuple(t.tactic_id for t in tactics),
                    tactic_names=tuple(t.name for t in tactics),
                    group_ids=tuple(g.group_id for g in groups),
                    group_names=tuple(g.name for g in groups),
                    software_ids=tuple(s.software_id for s in software),
                    software_names=tuple(s.name for s in software),
                    mitigation_ids=tuple(m.mitigation_id for m in mitigations),
                    mitigation_names=tuple(m.name for m in mitigations),
                    confidence=max(m.confidence for m in matches),
                    supporting_finding_ids=tuple(
                        sorted({m.finding_id for m in matches if m.finding_id})
                    ),
                )
            )

        resolved.sort(key=lambda r: r.confidence, reverse=True)
        return MitreCaseMappingOutput(
            technique_count=len(resolved),
            tactic_coverage=tactic_coverage,
            distinct_group_count=len(all_group_ids),
            distinct_software_count=len(all_software_ids),
            resolved_techniques=tuple(resolved),
            unresolved_technique_ids=tuple(sorted(unresolved)),
            top_techniques=tuple(resolved[: arguments.top_n]),
        )
