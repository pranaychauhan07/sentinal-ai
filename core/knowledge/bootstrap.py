"""`register_default_knowledge_sources` — the one place every concrete
`KnowledgeSource` (MITRE, plus the three ADR-0027 additions) is loaded and
registered into a `KnowledgeSourceRegistry`.

Mirrors `core.knowledge.mitre.bootstrap.load_mitre_dataset`'s "explicit,
injectable, not a module-level cached singleton" convention (constitution
§2, "avoid global state") — callers (today, `apps/api/main.py`'s startup
hook and tests) construct one registry and pass it around explicitly.

Never raises: a missing/malformed vendored data file degrades that one
source to "not registered" (logged at `ERROR`) rather than blocking every
other source or failing application startup — the same graceful-degradation
contract `core/memory`'s long-term-memory layer already has (constitution
§7).
"""

from __future__ import annotations

from core.config import Settings
from core.knowledge.detection.loader import load_detection_principles
from core.knowledge.detection.source import DetectionRuleSource
from core.knowledge.mitre.bootstrap import load_mitre_dataset
from core.knowledge.mitre.source import MitreAttackSource
from core.knowledge.models import KnowledgeSourceType
from core.knowledge.owasp.loader import load_owasp_categories
from core.knowledge.owasp.source import OwaspTop10Source
from core.knowledge.playbooks.loader import load_best_practices, load_incident_response_guidance
from core.knowledge.playbooks.source import SecurityPlaybookSource
from core.knowledge.registry import KnowledgeSourceRegistry
from core.logging import get_logger

_logger = get_logger(__name__)


def register_default_knowledge_sources(
    registry: KnowledgeSourceRegistry, settings: Settings
) -> KnowledgeSourceRegistry:
    """Registers MITRE ATT&CK (unmodified, existing loader) plus the three
    ADR-0027 knowledge sources (OWASP Top 10, security/incident-response
    playbooks, detection-engineering guidance) into `registry`, returning it
    for convenient chaining."""
    try:
        mitre_dataset = load_mitre_dataset(settings)
        registry.register(KnowledgeSourceType.MITRE_ATTACK, MitreAttackSource(mitre_dataset))
    except Exception as exc:  # noqa: BLE001 - one source failing must not block the others
        _logger.error("knowledge_source_registration_failed", source="mitre_attack", error=str(exc))

    try:
        categories = load_owasp_categories(settings.owasp_top10_data_path)
        registry.register(KnowledgeSourceType.OWASP_TOP10, OwaspTop10Source(categories))
    except Exception as exc:  # noqa: BLE001 - one source failing must not block the others
        _logger.error("knowledge_source_registration_failed", source="owasp_top10", error=str(exc))

    try:
        best_practices = load_best_practices(settings.security_best_practices_data_path)
        ir_guidance = load_incident_response_guidance(settings.incident_response_guidance_data_path)
        registry.register(
            KnowledgeSourceType.SECURITY_PLAYBOOK,
            SecurityPlaybookSource(
                best_practices=best_practices, incident_response_phases=ir_guidance
            ),
        )
    except Exception as exc:  # noqa: BLE001 - one source failing must not block the others
        _logger.error(
            "knowledge_source_registration_failed", source="security_playbook", error=str(exc)
        )

    try:
        principles = load_detection_principles(settings.detection_engineering_guidance_data_path)
        registry.register(KnowledgeSourceType.DETECTION_RULE, DetectionRuleSource(principles))
    except Exception as exc:  # noqa: BLE001 - one source failing must not block the others
        _logger.error(
            "knowledge_source_registration_failed", source="detection_rule", error=str(exc)
        )

    return registry
