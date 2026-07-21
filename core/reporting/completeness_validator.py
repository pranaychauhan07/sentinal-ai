"""`validate_completeness` — the task's named "Validate Completeness"
pipeline stage. Pure, deterministic (constitution §1.9): checks the
assembled `sections` tuple against `section_registry.REPORT_TYPE_SECTIONS`
for the requested `ReportType` — missing a required section, a duplicate
section type, or every section coming back empty are all reported, never
silently accepted.
"""

from __future__ import annotations

from collections import Counter

from core.reporting.models import ReportSection, ReportType, ReportValidationResult
from core.reporting.section_registry import REPORT_TYPE_SECTIONS


def validate_completeness(
    report_type: ReportType, sections: tuple[ReportSection, ...]
) -> ReportValidationResult:
    required = set(REPORT_TYPE_SECTIONS[report_type])
    present_types = [section.section_type for section in sections]
    counts = Counter(present_types)

    missing = tuple(sorted(required - set(present_types), key=lambda t: t.value))
    duplicates = tuple(
        sorted((t for t, count in counts.items() if count > 1), key=lambda t: t.value)
    )
    all_empty = bool(sections) and all(section.is_empty for section in sections)

    reasons: list[str] = []
    if missing:
        reasons.append(f"Missing required section(s): {', '.join(t.value for t in missing)}.")
    if duplicates:
        reasons.append(f"Duplicate section(s) generated: {', '.join(t.value for t in duplicates)}.")
    if all_empty:
        reasons.append("Every generated section is empty; no data was available for this case.")
    if not sections:
        reasons.append("No sections were generated at all.")

    is_complete = not missing and not duplicates and not all_empty and bool(sections)
    return ReportValidationResult(
        is_complete=is_complete,
        missing_section_types=missing,
        duplicate_section_types=duplicates,
        reasons=tuple(reasons),
    )
