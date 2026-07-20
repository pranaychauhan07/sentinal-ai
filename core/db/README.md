# core/db — Persistence (SQLAlchemy ORM)

**Purpose:** The Database Layer (`context/01_blueprint.md` §4). `models/` is a
package, one module per table (`models/case.py`, `models/case_note.py`,
`models/case_tag.py`, `models/evidence.py`,
`models/ioc.py`, `models/finding.py`, `models/finding_mitre_mapping.py`,
`models/mitre_tactic.py`, `models/mitre_technique.py`,
`models/mitre_software.py`, `models/mitre_group.py`,
`models/mitre_mitigation.py`, `models/timeline_event.py`,
`models/report.py`, `models/vulnerability.py`,
`models/linux_security_finding.py`), re-exported from `models/__init__.py`
exactly as blueprint §8 specifies — blueprint §8's full schema list is now
complete, plus `Vulnerability` (docs/adr/0017) and `LinuxSecurityFindingRow`
(docs/adr/0018). `session.py` provides the async SQLAlchemy session factory.
`migrations/` holds Alembic migrations.

**`Vulnerability` (docs/adr/0017-vulnerability-assessment-framework.md)**
mirrors `IOC`'s shape exactly — one persisted, scored
`core.vulnerabilities.models.ScoredVulnerability` per row, with both
`case_id` and `evidence_id` real foreign keys from the start (unlike `IOC`'s
original two-step tightening in ADR-0011/0014: `Case`/`Evidence` both
already existed by the time this table was introduced). Three independent,
optional CVSS slots (`cvss_v2_vector`/`cvss_v3_vector`/`cvss_v4_vector` +
matching base-score columns) — a single scan-report row commonly carries
both a v2 and a v3 score simultaneously. `core.db.vulnerability_repository.
VulnerabilityRepository` mirrors `IOCRepository`'s shape (`find_by_case`,
`find_by_evidence`, `find_by_cve`, `find_by_asset`, `mark_dismissed`,
`mark_false_positive`, `increment_occurrence`).

**`TimelineEventType` gained `VULNERABILITY_ASSESSED`** (docs/adr/0017),
extended additively via migration `b2a6f1c3d8e4`, mirroring `031e35cdb9e7`'s
identical dialect-branching pattern (`ALTER TYPE ... ADD VALUE` on
PostgreSQL, `batch_alter_table` column rebuild on SQLite) — the original
eight values are never renamed/removed.

**`LinuxSecurityFindingRow` (docs/adr/0018-linux-security-threat-hunting-
framework.md)** mirrors `Vulnerability`'s shape exactly — one persisted,
scored `core.linux_security.models.LinuxSecurityFinding` per row (grouped by
`(category, subject)`), with both `case_id` and `evidence_id` real foreign
keys from the start. `core.db.linux_security_finding_repository.
LinuxSecurityFindingRepository` mirrors `VulnerabilityRepository`'s shape
(`find_by_case`, `find_by_evidence`, `find_by_subject`, `mark_dismissed`,
`mark_false_positive`, `increment_occurrence`). **`TimelineEventType` gained
`LINUX_SECURITY_FINDING_DETECTED`**, extended additively via migration
`7f3d9a1b5c2e` (after `9c1e2a7d4b6f` creates the table), the same
dialect-branching pattern as `VULNERABILITY_ASSESSED`'s migration — the
original nine values are never renamed/removed.

**ADR-0015 (Case Management Extension)** additively extended `Case` with
`priority` (`CasePriority`), `risk_score`, `owner_id`/`assignee_id`, and
`labels` (freeform, unindexed JSON), and extended `CaseStatus` with five new
values (`escalated`/`on_hold`/`contained`/`resolved`/`archived` — the
original three are unchanged). Two new tables: `CaseNote` (editable analyst
commentary, distinct from `TimelineEvent.MANUAL_NOTE`'s immutable audit
record) and `CaseTag` (an indexed, unique-constrained `(case_id, tag)` join
table — deliberately not a Postgres-only `ARRAY` column, since this project
supports both PostgreSQL and SQLite). `CaseRepository.update_status` remains
unconditional CRUD; transition validation lives one layer up in
`core/services/case_lifecycle.py`, never inside `core/db` (which cannot
import `core/services` without a circular, upward dependency).

**`Evidence.case_id`, `IOC.case_id`, and `Finding.case_id` are now real
foreign keys** to `cases.id` — the follow-up migration ADR-0011/0012/0013
each owed (`7ae8f470d5e7`, applied via `op.batch_alter_table` for SQLite
compatibility) landed once `Case` existed (`docs/adr/0014-case-model-and-
first-api-routes-shape.md` point 3). `IOC.evidence_id`/`Finding.
primary_evidence_id`/`Finding.primary_ioc_id` were already real foreign keys.
`Report.case_id`/`TimelineEvent.case_id` are real foreign keys from the
start, since `Case` existed before they were created.

**The five `mitre_*` tables are reference tables, seeded only by
`scripts/mitre/import_attack_bundle.py`, never written by application
logic.** Each has a surrogate UUID PK plus a unique indexed business column
(`technique_id`, `tactic_id`, etc.) and an `attack_spec_version` column — a
new ATT&CK release is additive new rows, never an in-place mutation of an
existing one (constitution §7). `finding_mitre_mappings` is the real
many-to-many join table between `Finding` and `MitreTechnique`.

**Responsibility:** System-of-record persistence only. ChromaDB (in
`core/memory/long_term.py`) is retrieval-only and never authoritative.

**Why it exists:** A multi-case, multi-evidence-type system has real relational
structure; see `docs/adr/0004-relational-database.md` for why PostgreSQL (with
SQLite as a drop-in fallback) was chosen over a flat-file or pure-vector store.

**Future expansion:** Multi-user/RBAC tables are additive to this schema, not a
rewrite of it.
