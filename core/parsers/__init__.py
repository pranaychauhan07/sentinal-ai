"""Parser Layer — see core/parsers/README.md.

Public surface: `core.parsers.models` (the canonical `NormalizedEvidence`
contract), `core.parsers.registry.default_parser_registry`,
`core.parsers.factory.select_parser`. Concrete parsers are never imported
directly by callers outside this package — they're resolved by name/type
through the registry/factory.
"""

from core.parsers.base import BaseParser, RawEvidenceInput
from core.parsers.factory import select_parser
from core.parsers.models import (
    ChainOfCustody,
    EvidenceRecord,
    EvidenceType,
    NormalizedEvidence,
    Severity,
)
from core.parsers.registry import ParserRegistry, default_parser_registry

__all__ = [
    "BaseParser",
    "RawEvidenceInput",
    "ChainOfCustody",
    "EvidenceRecord",
    "EvidenceType",
    "NormalizedEvidence",
    "Severity",
    "ParserRegistry",
    "default_parser_registry",
    "select_parser",
]
