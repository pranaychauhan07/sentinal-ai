"""Domain models — one module per table (`evidence.py`, and future
`case.py`/`finding.py`/`mitre_technique.py`/`timeline_event.py`/`report.py`
as Milestone M1 adds them), re-exported here so
`from core.db.models import Evidence` keeps working regardless of which
sibling module actually defines it.

Importing this package (rather than each submodule individually) is also
what `core/db/migrations/env.py` relies on to populate `Base.metadata` for
Alembic autogeneration — every new domain module must be imported below in
the same PR that introduces it.
"""

from core.db.models.evidence import Evidence, EvidenceStatus
from core.db.models.ioc import IOC, IOCStatus

__all__ = ["IOC", "Evidence", "EvidenceStatus", "IOCStatus"]
