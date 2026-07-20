"""Persistence Detection — cross-category aggregation of already-produced
candidates from `cron_analyzer.py`, `service_analyzer.py`, and
`privilege_escalation.py` into `persistence_mechanism` findings. This
module's job is aggregation, not re-implementing cron/service/account
parsing (constitution §1.3/§1.4, single responsibility) — the line-parsing
itself stays owned by those three modules.
"""

from __future__ import annotations

from core.linux_security.models import (
    LinuxSecurityCandidate,
    LinuxSecurityFindingCategory,
)

#: Categories this module treats as persistence signals when they co-occur
#: for the same subject — a suspicious cron job or service is persistence by
#: itself; a new-user-creation only counts as persistence when paired with a
#: subsequent privilege escalation for that same user (a bare new account is
#: routine administration, not evidence of persistence on its own).
_DIRECT_PERSISTENCE_CATEGORIES: frozenset[LinuxSecurityFindingCategory] = frozenset(
    {
        LinuxSecurityFindingCategory.SUSPICIOUS_CRON,
        LinuxSecurityFindingCategory.SUSPICIOUS_SERVICE,
    }
)


def detect_persistence_mechanisms(
    cron_candidates: list[LinuxSecurityCandidate],
    service_candidates: list[LinuxSecurityCandidate],
    privilege_escalation_candidates: list[LinuxSecurityCandidate],
) -> list[LinuxSecurityCandidate]:
    """Re-flags direct persistence signals (suspicious cron/service) and the
    new-user-creation-then-escalation combined pattern (already emitted by
    `privilege_escalation.py` as `PRIVILEGE_ESCALATION` with
    `context["pattern"] == "new_user_then_group_escalation"`) under the
    `PERSISTENCE_MECHANISM` category, so a case view can answer "what
    persists across reboots/sessions" directly."""
    persistence: list[LinuxSecurityCandidate] = []

    for candidate in (*cron_candidates, *service_candidates):
        if candidate.category in _DIRECT_PERSISTENCE_CATEGORIES:
            persistence.append(
                candidate.model_copy(
                    update={
                        "category": LinuxSecurityFindingCategory.PERSISTENCE_MECHANISM,
                        "context": {**candidate.context, "original_category": candidate.category},
                    }
                )
            )

    for candidate in privilege_escalation_candidates:
        if candidate.context.get("pattern") == "new_user_then_group_escalation":
            persistence.append(
                candidate.model_copy(
                    update={
                        "category": LinuxSecurityFindingCategory.PERSISTENCE_MECHANISM,
                        "context": {**candidate.context, "original_category": candidate.category},
                    }
                )
            )

    return persistence
