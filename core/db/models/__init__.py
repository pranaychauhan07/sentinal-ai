"""Domain models — one module per table, re-exported here so
`from core.db.models import Evidence` keeps working regardless of which
sibling module actually defines it.

Importing this package (rather than each submodule individually) is also
what `core/db/migrations/env.py` relies on to populate `Base.metadata` for
Alembic autogeneration — every new domain module must be imported below in
the same PR that introduces it.
"""

from core.db.models.case import Case, CasePriority, CaseStatus
from core.db.models.case_note import CaseNote
from core.db.models.case_tag import CaseTag
from core.db.models.evidence import Evidence, EvidenceStatus
from core.db.models.finding import Finding
from core.db.models.finding_mitre_mapping import FindingMitreMapping
from core.db.models.ioc import IOC, IOCStatus
from core.db.models.mitre_group import MitreGroup
from core.db.models.mitre_mitigation import MitreMitigation
from core.db.models.mitre_software import MitreSoftware
from core.db.models.mitre_tactic import MitreTactic
from core.db.models.mitre_technique import MitreTechnique
from core.db.models.report import Report, ReportType
from core.db.models.timeline_event import TimelineEvent, TimelineEventType

__all__ = [
    "IOC",
    "Case",
    "CaseNote",
    "CasePriority",
    "CaseStatus",
    "CaseTag",
    "Evidence",
    "EvidenceStatus",
    "Finding",
    "FindingMitreMapping",
    "IOCStatus",
    "MitreGroup",
    "MitreMitigation",
    "MitreSoftware",
    "MitreTactic",
    "MitreTechnique",
    "Report",
    "ReportType",
    "TimelineEvent",
    "TimelineEventType",
]
