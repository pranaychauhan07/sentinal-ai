"""`LinuxSecurityNormalizer` — turns `core.parsers.models.NormalizedEvidence`
records (from `SSH_AUTH`/`SYSLOG` evidence) into this package's own
`LinuxLogEvent`s (constitution §1.9: deterministic, pure, no LLM judgment
involved in canonicalization). Mirrors
`core.vulnerabilities.normalizer.VulnerabilityNormalizer`'s role.

Includes a best-effort, documented supplement for journald JSON exports:
journald's `_`-prefixed field names (`_COMM`, `_SYSTEMD_UNIT`,
`SYSLOG_IDENTIFIER`, `MESSAGE`, `_PID`) are not yet mapped by
`core.parsers.field_heuristics`'s generic key-alias tables (an honest,
documented gap — same spirit as ADR-0017's CVSS v4.0 gap), so
`_read_journald_fields` opportunistically reads them directly from
`EvidenceRecord.normalized_fields` when the standard fields
(`event_type`/`raw_line` message) come back empty. This supplement only
fires when journald-shaped keys are actually present on the record; it is
never the primary path (`SshAuthParser`/`SyslogParser`'s own structured
`event_type`/`normalized_fields["message"]` always wins when present).

Note: `core.services.linux_security_service.assess_linux_security()` only
ever calls this normalizer against `SSH_AUTH`/`SYSLOG` evidence (see that
module's docstring for why `EvidenceType.JSON` is deliberately excluded from
that gating) — so in practice this journald supplement is dormant until a
future evidence-routing change feeds journald JSON exports through this
package. Kept here now, documented honestly, rather than silently omitted.
"""

from __future__ import annotations

import re
from typing import Any

from core.linux_security.models import LinuxLogEvent
from core.logging import get_logger
from core.parsers.models import EvidenceRecord, NormalizedEvidence

_logger = get_logger(__name__)

#: Journald export field names this package reads as a best-effort
#: supplement (see module docstring). Order matters: first match wins.
_JOURNALD_PROCESS_KEYS: tuple[str, ...] = ("SYSLOG_IDENTIFIER", "_COMM", "_SYSTEMD_UNIT")
_JOURNALD_MESSAGE_KEYS: tuple[str, ...] = ("MESSAGE",)

#: Strips ASCII control characters (including embedded newlines/carriage
#: returns) from any field that ends up in a log line or a finding
#: title/description — a log-injection guard (constitution §10, "input
#: validation") so an attacker-controlled username/message can't forge
#: additional fake log lines in downstream rendering. Tab (`\x09`) is
#: deliberately preserved (harmless whitespace); every other control
#: character, including `\n`/`\r`, is stripped.
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")


def sanitize_text(value: str | None, *, max_length: int = 4096) -> str:
    """Removes control characters and truncates — the one place every
    analyzer's free-text input is cleaned, so a malformed/adversarial log
    line (embedded control chars, an absurdly long field) degrades to a
    safe, bounded string rather than propagating raw (constitution §10)."""
    if not value:
        return ""
    cleaned = _CONTROL_CHAR_RE.sub("", value)
    return cleaned[:max_length]


def _read_journald_fields(fields: dict[str, Any]) -> tuple[str | None, str | None]:
    """Returns `(process, message)` read from journald-shaped keys, or
    `(None, None)` if none are present. See module docstring."""
    process = next((str(fields[key]) for key in _JOURNALD_PROCESS_KEYS if fields.get(key)), None)
    message = next((str(fields[key]) for key in _JOURNALD_MESSAGE_KEYS if fields.get(key)), None)
    return process, message


class LinuxSecurityNormalizer:
    """Stateless, deterministic canonicalization. One instance is safe to
    share across a whole pipeline run (no internal mutable state)."""

    def normalize(self, evidence: NormalizedEvidence) -> tuple[list[LinuxLogEvent], int]:
        """Returns `(events, skipped_count)`. A record with no usable
        timestamp *and* no process/message signal is skipped (not
        discarded silently — the caller records `skipped_count` on
        `NormalizedLinuxSecurityIntel.skipped_record_count`), matching
        constitution §1.7's "degrade that one record, never abort the
        artifact" rule."""
        events: list[LinuxLogEvent] = []
        skipped = 0
        for record in evidence.records:
            try:
                event = self._event_from_record(record, evidence)
            except Exception as exc:  # noqa: BLE001 - a malformed record must never abort the artifact
                _logger.warning(
                    "linux_security_record_skipped",
                    evidence_id=str(evidence.evidence_id),
                    line_number=record.line_number,
                    error=str(exc),
                )
                skipped += 1
                continue
            if event is None:
                skipped += 1
                continue
            events.append(event)
        return events, skipped

    def _event_from_record(
        self, record: EvidenceRecord, evidence: NormalizedEvidence
    ) -> LinuxLogEvent | None:
        fields = record.normalized_fields
        process = record.event_type
        message = str(fields.get("message", "")) if fields.get("message") else record.raw_line

        if not process and not message:
            journald_process, journald_message = _read_journald_fields(fields)
            process = process or journald_process
            message = message or journald_message or ""

        if record.timestamp is None and not process and not message:
            return None

        return LinuxLogEvent(
            timestamp=record.timestamp,
            host=sanitize_text(record.host, max_length=255) or None,
            user=sanitize_text(record.user, max_length=255) or None,
            ip_address=sanitize_text(record.ip_address, max_length=64) or None,
            process=sanitize_text(process, max_length=128) or None,
            raw_message=sanitize_text(message, max_length=4096),
            evidence_id=evidence.evidence_id,
            line_number=record.line_number,
        )
