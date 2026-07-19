"""Threat Intelligence & IOC Extraction Framework — see
core/threat_intel/README.md.

Public surface: `core.threat_intel.models` (the canonical `IOCRecord`/
`NormalizedThreatIntel` contracts), `core.threat_intel.registry.
default_extractor_registry`, `core.threat_intel.provider_registry.
default_provider_registry`. Concrete extractors/providers are resolved by
name/type through the registries, never imported directly by callers
outside this package.
"""

from core.threat_intel.base import BaseIOCExtractor
from core.threat_intel.models import (
    AttributionRecord,
    DetectionRule,
    IOCClassification,
    IOCQuery,
    IOCRecord,
    IOCType,
    NormalizedThreatIntel,
    RuleMatchResult,
    RuleType,
    ScoredIOC,
    SourceReliability,
    ThreatCategory,
    ThreatScore,
    ThreatSeverity,
)
from core.threat_intel.provider_registry import ProviderRegistry, default_provider_registry
from core.threat_intel.registry import ExtractorRegistry, default_extractor_registry

__all__ = [
    "AttributionRecord",
    "BaseIOCExtractor",
    "DetectionRule",
    "ExtractorRegistry",
    "IOCClassification",
    "IOCQuery",
    "IOCRecord",
    "IOCType",
    "NormalizedThreatIntel",
    "ProviderRegistry",
    "RuleMatchResult",
    "RuleType",
    "ScoredIOC",
    "SourceReliability",
    "ThreatCategory",
    "ThreatScore",
    "ThreatSeverity",
    "default_extractor_registry",
    "default_provider_registry",
]
