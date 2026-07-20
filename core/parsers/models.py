"""Canonical evidence schema — context/01_blueprint.md's "Parser Layer" output
contract. Every parser in this package returns a :class:`NormalizedEvidence`;
every downstream consumer (future agents, `core/services/evidence_service.py`,
`core/db/models/evidence.py`) reads only this shape (constitution §1.2).

Two levels, deliberately kept distinct:

- :class:`EvidenceRecord` — one parsed *event* (a single log line, a single
  Nmap host, a single JSON object) with the per-event fields the task's
  canonical schema calls for (timestamp/host/user/ip/event_type/severity/raw
  content).
- :class:`NormalizedEvidence` — the per-*artifact* container a parser returns
  for one uploaded file, holding zero or more `EvidenceRecord`s plus
  artifact-level metadata, confidence, and chain-of-custody. This is the
  level `Evidence.parsed_json` (core/db/models/evidence.py) persists.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EvidenceType(StrEnum):
    """Closed set of evidence formats this framework knows how to parse.

    More granular than `context/01_blueprint.md` §8's illustrative
    `evidence_type` enum (`email/log/nmap/nessus/source_code/incident_note`)
    — refined here to the specific formats `core/parsers` implements, per
    `docs/adr/0011-evidence-ingestion-pipeline-shape.md` point 3. Additive:
    nothing has been built against the coarser enum yet.
    """

    SSH_AUTH = "ssh_auth"
    APACHE_ACCESS = "apache_access"
    APACHE_ERROR = "apache_error"
    SYSLOG = "syslog"
    WINDOWS_EVENT = "windows_event"
    JSON = "json"
    CSV = "csv"
    NMAP_XML = "nmap_xml"
    PLAIN_TEXT = "plain_text"
    EMAIL = "email"
    NESSUS_XML = "nessus_xml"
    NESSUS_CSV = "nessus_csv"
    OPENVAS_XML = "openvas_xml"
    OPENVAS_CSV = "openvas_csv"
    LINUX_COMMAND_INPUT = "linux_command_input"
    HTTP_TRANSACTION = "http_transaction"
    SOURCE_CODE = "source_code"
    UNKNOWN = "unknown"


class Severity(StrEnum):
    """Shared severity scale — mirrors the Low/Medium/High/Critical scale
    named throughout blueprint §7 for specialist-agent findings, plus `INFO`
    for routine, non-security-relevant events (e.g. a successful login)."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ChainOfCustody(BaseModel):
    """Custody metadata for one uploaded artifact — who/when it entered the
    system and what it hashed to, so downstream reporting can show an
    unbroken evidentiary trail (blueprint §1's "every step justified")."""

    model_config = ConfigDict(frozen=True)

    ingested_at: datetime
    ingested_by: str
    original_filename: str
    sha256: str
    file_size_bytes: int


class EvidenceRecord(BaseModel):
    """One normalized event extracted from an evidence artifact."""

    model_config = ConfigDict(frozen=True)

    line_number: int | None = None
    timestamp: datetime | None = None
    host: str | None = None
    user: str | None = None
    ip_address: str | None = None
    event_type: str | None = None
    severity: Severity = Severity.INFO
    raw_line: str = ""
    normalized_fields: dict[str, Any] = Field(default_factory=dict)


class NormalizedEvidence(BaseModel):
    """The Parser Layer's one output contract — every parser's `parse()`
    returns this, regardless of format. Never silently drops data
    (constitution §1.7): anything a parser couldn't map into a structured
    `EvidenceRecord` field goes into `unparsed_fragments` instead of being
    discarded.
    """

    model_config = ConfigDict(frozen=True)

    evidence_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    evidence_type: EvidenceType
    source: str
    parser_name: str
    parser_version: str
    confidence: float = Field(ge=0.0, le=1.0)
    records: list[EvidenceRecord] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    unparsed_fragments: list[str] = Field(default_factory=list)
    chain_of_custody: ChainOfCustody
    parsed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def record_count(self) -> int:
        return len(self.records)
