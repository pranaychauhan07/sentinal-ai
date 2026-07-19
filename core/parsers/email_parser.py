"""Email parser — blueprint §6's `email_parser.py`, the first attacker-
controlled-text evidence format this framework ingests (Milestone M2).

Uses only the stdlib `email` package (no new dependency, per constitution
§10 — `email.message_from_string` with `email.policy.default` for RFC 5322/
MIME-aware header decoding). Deliberately does *not* attempt IOC extraction,
sender-reputation scoring, or phishing judgment here — this parser only
extracts structure. `core.threat_intel.extractor.IOCExtractionEngine` already
regex-scans every `EvidenceRecord.raw_line` for emails/URLs/domains, so the
header/body text this parser emits is picked up by the existing pipeline with
zero new extraction code; `core.agents.phishing_agent.PhishingAgent` is the
only place that renders a security verdict from what's extracted here.

Known limitation (documented, not silently overstated): this parser works
from the artifact's single decoded-text representation
(`core.parsers.detection.detect_encoding`), matching every other parser in
this package. A genuinely multipart MIME message with per-part, non-UTF-8
charsets (rare in practice for the phishing-triage use case) may not decode
every part correctly — a real limitation, not a defect masked as one.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from email import message_from_string, policy
from email.message import EmailMessage
from email.utils import getaddresses, parsedate_to_datetime

from core.parsers.base import BaseParser, RawEvidenceInput
from core.parsers.models import (
    EvidenceRecord,
    EvidenceType,
    NormalizedEvidence,
    Severity,
)

#: Header lines an RFC 5322 message is expected to open with — used by
#: `sniff()` to disambiguate a `.eml`/`.txt` upload from a plain log/text
#: file, mirroring every other parser's own header-hint heuristic
#: (`_SSH_AUTH_HINT_RE`, `_APACHE_COMBINED_RE`, ...).
_HEADER_LINE_RE = re.compile(
    r"^(From|To|Cc|Bcc|Subject|Date|Message-ID|Reply-To|Return-Path):", re.IGNORECASE
)
_REQUIRED_HEADER_HINTS = ("from", "subject")


def _addresses_to_text(pairs: list[tuple[str, str]]) -> str:
    """Renders `(display_name, address)` pairs back to a header-shaped string
    so `IOCExtractionEngine`'s regex scan over `raw_line` finds the embedded
    email address(es) exactly as it would in a raw header line."""
    return ", ".join(f'"{name}" <{addr}>' if name else addr for name, addr in pairs if addr)


class EmailParser(BaseParser):
    """Parses a single RFC 5322 email (`.eml`) into header/body
    `EvidenceRecord`s. Blueprint §7 (Phishing Investigation Agent): "sender/
    domain analysis, URL risk scoring, content social-engineering detection,
    attachment risk" all consume this parser's *output* — none of that
    judgment happens here (constitution §1.4, single responsibility)."""

    name = "email"
    description = "Parses RFC 5322 email messages (.eml) for phishing triage."
    evidence_type = EvidenceType.EMAIL
    supported_extensions = (".eml",)
    supported_mime_types = ("message/rfc822",)

    def sniff(self, raw: RawEvidenceInput, decoded_text: str) -> float:
        sample_lines = [line for line in decoded_text.splitlines()[:30] if line.strip()]
        hits = sum(1 for line in sample_lines if _HEADER_LINE_RE.match(line))
        if not hits:
            return 0.0
        return min(1.0, hits / 3)

    def validate_content(self, raw: RawEvidenceInput, decoded_text: str) -> None:
        sample_lines = [line for line in decoded_text.splitlines()[:30] if line.strip()]
        header_names = {
            line.split(":", maxsplit=1)[0].strip().lower()
            for line in sample_lines
            if _HEADER_LINE_RE.match(line)
        }
        self.raise_if_invalid(
            any(hint in header_names for hint in _REQUIRED_HEADER_HINTS),
            "Content has no recognizable email headers (From/Subject).",
        )

    def parse_content(self, raw: RawEvidenceInput, decoded_text: str) -> NormalizedEvidence:
        # `email.message_from_string` never raises on malformed input under
        # `policy.default` — it records parse issues on `message.defects`
        # instead (the stdlib module's own degrade-not-reject design). The
        # `validate_content` header check above is this parser's actual
        # malformed-input gate.
        message = message_from_string(decoded_text, policy=policy.default)
        assert isinstance(message, EmailMessage)  # noqa: S101 - policy.default guarantees this type

        records = [self._header_record(message), self._body_record(message)]
        metadata = self._extract_metadata(message)
        confidence = 1.0 if metadata["from_address"] and metadata["subject"] else 0.6

        return NormalizedEvidence(
            evidence_type=self.evidence_type,
            source=raw.filename,
            parser_name=self.name,
            parser_version=self.version,
            confidence=confidence,
            records=records,
            metadata=metadata,
            unparsed_fragments=[],
            chain_of_custody=self._chain_of_custody(raw),
        )

    def _header_record(self, message: EmailMessage) -> EvidenceRecord:
        from_pairs = getaddresses(message.get_all("From", []))
        reply_to_pairs = getaddresses(message.get_all("Reply-To", []))
        to_pairs = getaddresses(message.get_all("To", []))
        subject = message.get("Subject", "")
        timestamp = self._parse_date(message.get("Date"))

        header_text = (
            f"From: {_addresses_to_text(from_pairs)}\n"
            f"Reply-To: {_addresses_to_text(reply_to_pairs)}\n"
            f"To: {_addresses_to_text(to_pairs)}\n"
            f"Subject: {subject}\n"
            f"Message-ID: {message.get('Message-ID', '')}\n"
        )

        return EvidenceRecord(
            timestamp=timestamp,
            user=from_pairs[0][1] if from_pairs else None,
            event_type="email_header",
            severity=Severity.INFO,
            raw_line=header_text,
            normalized_fields={
                "subject": subject,
                "from_display": from_pairs[0][0] if from_pairs else "",
                "from_address": from_pairs[0][1] if from_pairs else "",
                "reply_to_address": reply_to_pairs[0][1] if reply_to_pairs else "",
                "to_addresses": [addr for _name, addr in to_pairs if addr],
            },
        )

    def _body_record(self, message: EmailMessage) -> EvidenceRecord:
        body_text = self._extract_body_text(message)
        return EvidenceRecord(
            event_type="email_body",
            severity=Severity.INFO,
            raw_line=body_text,
            normalized_fields={"body_length": len(body_text)},
        )

    def _extract_body_text(self, message: EmailMessage) -> str:
        body_part = message.get_body(preferencelist=("plain", "html"))
        if body_part is None:
            return ""
        try:
            return str(body_part.get_content())
        except (KeyError, UnicodeDecodeError, LookupError):
            payload = body_part.get_payload(decode=True)
            return payload.decode("utf-8", errors="replace") if isinstance(payload, bytes) else ""

    def _extract_metadata(self, message: EmailMessage) -> dict[str, object]:
        from_pairs = getaddresses(message.get_all("From", []))
        reply_to_pairs = getaddresses(message.get_all("Reply-To", []))
        attachments = [
            {
                "filename": part.get_filename() or "",
                "content_type": part.get_content_type(),
            }
            for part in message.iter_attachments()
        ]
        return {
            "subject": message.get("Subject", ""),
            "from_address": from_pairs[0][1] if from_pairs else "",
            "from_display": from_pairs[0][0] if from_pairs else "",
            "reply_to_address": reply_to_pairs[0][1] if reply_to_pairs else "",
            "message_id": message.get("Message-ID", ""),
            "date": message.get("Date", ""),
            "attachments": attachments,
            "is_multipart": message.is_multipart(),
        }

    def _parse_date(self, raw_date: str | None) -> datetime | None:
        if not raw_date:
            return None
        try:
            parsed = parsedate_to_datetime(raw_date)
        except (TypeError, ValueError):
            return None
        return parsed.astimezone(UTC) if parsed.tzinfo else parsed
