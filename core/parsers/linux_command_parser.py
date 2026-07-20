"""``LinuxCommandInputParser`` — evidence intake for the Linux Security Agent
(blueprint §7's command/permission advisor; `docs/adr/0019-linux-security-
advisor-agent.md`).

Deliberately dumb/generic, matching every other parser in this package:
produces exactly one `EvidenceRecord` per non-blank input line
(`event_type="linux_input_line"`, `raw_line=<the line>`). It does **not**
classify a line as an `ls -l` permission entry vs. a shell command vs. a
`chmod` call — that deeper semantic classification is
`core.linux_advisor.advisory_engine.LinuxSecurityAdvisoryEngine`'s job
(constitution's "parsers extract structure only where unambiguous" precedent,
already applied identically to sudo/cron message parsing in
`core/linux_security` — a *different*, already-complete package this parser
must never be confused with).

`sniff()` gives this parser a real, above-`PlainTextParser` (0.1) confidence
when it recognizes one of three shapes: an `ls -l`-style permission-string
prefix, a shebang line, or a line starting with a small set of
security-relevant command names — registered in `core.parsers.registry` at
priority 3 (heuristic, not a fully structured format like Nessus XML).
"""

from __future__ import annotations

import re

from core.parsers.base import BaseParser, RawEvidenceInput
from core.parsers.models import EvidenceRecord, EvidenceType, NormalizedEvidence, Severity

#: The `ls -l` permission-string prefix: a file-type char followed by three
#: rwx-or-special triplets. Matches `-rwxr-xr-x`, `drwxrwxrwt`, `lrwxrwxrwx`.
_LS_PERMISSION_PREFIX = re.compile(r"^[bcdlpsD-][r-][w-][xsS-][r-][w-][xsS-][r-][w-][xtT-]")

#: A shebang line, e.g. `#!/bin/bash`.
_SHEBANG_PREFIX = re.compile(r"^#!\s*/bin/")

#: Security-relevant command names this parser recognizes as a signal that a
#: line is a shell command worth the advisor's attention (not an exhaustive
#: allowlist of every command the advisor can analyze — `command_analyzer.py`
#: handles arbitrary command lines; this is only a `sniff()` confidence
#: signal).
_SECURITY_RELEVANT_COMMANDS: frozenset[str] = frozenset(
    {
        "chmod",
        "chown",
        "chgrp",
        "sudo",
        "umask",
        "rm",
        "curl",
        "wget",
        "useradd",
        "usermod",
        "passwd",
        "systemctl",
    }
)

#: Confidence returned when a line matches one of the three recognized
#: shapes — above `PlainTextParser`'s 0.1, low enough that a fully structured
#: parser (Nessus XML, etc.) always wins a tie-break.
_SNIFF_CONFIDENCE_MATCH = 0.4
_SNIFF_CONFIDENCE_NONE = 0.0


def _first_token(line: str) -> str:
    stripped = line.strip()
    if not stripped:
        return ""
    return stripped.split(maxsplit=1)[0]


def _looks_security_relevant(line: str) -> bool:
    return _first_token(line) in _SECURITY_RELEVANT_COMMANDS


class LinuxCommandInputParser(BaseParser):
    name = "linux_command_input"
    description = (
        "Parser for raw Linux command strings and ls -l style permission "
        "listings — one EvidenceRecord per non-blank line, no deep "
        "classification (that is the Linux Security Agent's job)."
    )
    evidence_type = EvidenceType.LINUX_COMMAND_INPUT
    #: `.txt` is intentionally also claimed here (shared with
    #: `PlainTextParser`) so that a `.txt` upload containing recognizable
    #: command/permission content is routed here via `sniff()` rather than
    #: always falling to the plain-text fallback — see
    #: `core.parsers.factory._best_sniff_match`, which breaks an
    #: extension tie using each candidate's own `sniff()` confidence.
    supported_extensions = (".sh", ".cmd", ".txt")
    supported_mime_types = ("text/x-shellscript",)

    def sniff(self, raw: RawEvidenceInput, decoded_text: str) -> float:
        for line in decoded_text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if (
                _LS_PERMISSION_PREFIX.match(stripped)
                or _SHEBANG_PREFIX.match(stripped)
                or _looks_security_relevant(stripped)
            ):
                return _SNIFF_CONFIDENCE_MATCH
        return _SNIFF_CONFIDENCE_NONE

    def validate_content(self, raw: RawEvidenceInput, decoded_text: str) -> None:
        self.raise_if_invalid(bool(decoded_text.strip()), "Linux command input is empty.")

    def parse_content(self, raw: RawEvidenceInput, decoded_text: str) -> NormalizedEvidence:
        records: list[EvidenceRecord] = []
        for line_number, raw_line in enumerate(decoded_text.splitlines(), start=1):
            if not raw_line.strip():
                continue
            records.append(
                EvidenceRecord(
                    line_number=line_number,
                    event_type="linux_input_line",
                    severity=Severity.INFO,
                    raw_line=raw_line,
                    normalized_fields={},
                )
            )
        return NormalizedEvidence(
            evidence_type=self.evidence_type,
            source=raw.filename,
            parser_name=self.name,
            parser_version=self.version,
            confidence=0.6 if records else 0.1,
            records=records,
            metadata={"line_count": len(records)},
            unparsed_fragments=[],
            chain_of_custody=self._chain_of_custody(raw),
        )
