"""CVSS Calculator — `context/01_blueprint.md` §6's named
`core/knowledge/cvss_calculator.py`: deterministic CVSS vector parsing and
base-score computation (constitution §1.9, "a CVSS score ... is computed by
a plain function, never by asking an LLM").

Implements the official, published NVD/FIRST base-score formulas for CVSS
v2.0 and v3.0/3.1 (the two schemes with a public, closed-form base-score
formula). **CVSS v4.0 support is deliberately scope-cut to vector parsing
and format validation only** — v4.0's base score is defined by a
~90,000-row MacroVector lookup table (FIRST's official specification), not
a closed-form formula; reimplementing that table incorrectly would be worse
than the documented gap. Every v4.0 vector this module accepts is validated
and stored; its numeric severity relies on the scanner's own reported score
(`core.vulnerabilities`' callers already expect this — see that package's
README).

Read-only, reference-formula code — no runtime state, no I/O, no network.
"""

from __future__ import annotations

import math
import re
from enum import StrEnum
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

from core.exceptions import ValidationError


class CVSSVectorParseError(ValidationError):
    """A CVSS vector string is malformed or uses an unrecognized metric
    value — narrow, precisely-catchable per constitution §5 ("every tool
    module defines its own narrow exception classes"), and a subclass of
    `core.exceptions.AppError` so it maps cleanly onto the shared API error
    envelope if ever raised across `apps/api` (constitution §9)."""

    code = "CVSS_VECTOR_PARSE_ERROR"

    def __init__(self, message: str, *, vector: str) -> None:
        super().__init__(message, details={"vector": vector})
        self.vector = vector


class CvssVersion(StrEnum):
    """Closed set of CVSS schemes this module recognizes."""

    V2 = "2.0"
    V3_0 = "3.0"
    V3_1 = "3.1"
    V4_0 = "4.0"


class CvssSeverity(StrEnum):
    """This module's own severity scale (constitution §3: each leaf package
    owns its own severity scale rather than reusing a sibling's directly —
    matching `core.threat_intel.models.ThreatSeverity`'s and
    `core.findings.models.FindingSeverity`'s identical precedent).
    `core.vulnerabilities.severity` maps this onto its own
    `VulnerabilitySeverity` exactly the way `core.findings.severity` maps
    `ThreatSeverity` onto `FindingSeverity`."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CvssScore(BaseModel):
    """One computed (or, for v4.0, pass-through-only) CVSS assessment."""

    model_config = ConfigDict(frozen=True)

    version: CvssVersion
    vector: str
    base_score: float | None = Field(default=None, ge=0.0, le=10.0)
    severity: CvssSeverity


#: Official CVSS qualitative severity-rating thresholds (FIRST's published
#: scale, identical across v2/v3/v4; v2 has no official "None" band — 0.0 is
#: treated as `INFO` here for scale consistency).
def classify_cvss_severity(base_score: float) -> CvssSeverity:
    """Pure, deterministic bucketing — never computed by an LLM
    (constitution §1.9)."""
    if base_score <= 0.0:
        return CvssSeverity.INFO
    if base_score < 4.0:
        return CvssSeverity.LOW
    if base_score < 7.0:
        return CvssSeverity.MEDIUM
    if base_score < 9.0:
        return CvssSeverity.HIGH
    return CvssSeverity.CRITICAL


def _cvss_roundup(value: float) -> float:
    """The official CVSS v3.x "Roundup" function (FIRST specification):
    rounds up to the nearest 0.1, correcting the floating-point-comparison
    pitfalls a naive `round()` has at exact tenths."""
    int_value = round(value * 100_000)
    if int_value % 10_000 == 0:
        return int_value / 100_000.0
    return (math.floor(int_value / 10_000) + 1) / 10.0


# --- CVSS v2 ------------------------------------------------------------

_V2_METRIC_ORDER: tuple[str, ...] = ("AV", "AC", "Au", "C", "I", "A")
_V2_WEIGHTS: dict[str, dict[str, float]] = {
    "AV": {"L": 0.395, "A": 0.646, "N": 1.0},
    "AC": {"H": 0.35, "M": 0.61, "L": 0.71},
    "Au": {"M": 0.45, "S": 0.56, "N": 0.704},
    "C": {"N": 0.0, "P": 0.275, "C": 0.660},
    "I": {"N": 0.0, "P": 0.275, "C": 0.660},
    "A": {"N": 0.0, "P": 0.275, "C": 0.660},
}


class CvssV2Vector(BaseModel):
    """Parsed CVSS v2 base metrics (e.g. `AV:N/AC:L/Au:N/C:P/I:P/A:N`)."""

    model_config = ConfigDict(frozen=True)

    attack_vector: str
    attack_complexity: str
    authentication: str
    confidentiality_impact: str
    integrity_impact: str
    availability_impact: str


def parse_cvss_v2_vector(vector: str) -> CvssV2Vector:
    """Parses a bare CVSS v2 base vector string. Raises
    `CVSSVectorParseError` on any malformed or unrecognized component."""
    stripped = vector.strip()
    components: dict[str, str] = {}
    for part in stripped.split("/"):
        if ":" not in part:
            raise CVSSVectorParseError(f"Malformed CVSS v2 metric segment: {part!r}", vector=vector)
        key, _, value = part.partition(":")
        components[key] = value

    for metric in _V2_METRIC_ORDER:
        if metric not in components:
            raise CVSSVectorParseError(
                f"Missing required CVSS v2 metric '{metric}'.", vector=vector
            )
        if components[metric] not in _V2_WEIGHTS[metric]:
            raise CVSSVectorParseError(
                f"Unrecognized value '{components[metric]}' for CVSS v2 metric '{metric}'.",
                vector=vector,
            )

    return CvssV2Vector(
        attack_vector=components["AV"],
        attack_complexity=components["AC"],
        authentication=components["Au"],
        confidentiality_impact=components["C"],
        integrity_impact=components["I"],
        availability_impact=components["A"],
    )


def calculate_cvss_v2_base_score(parsed: CvssV2Vector) -> float:
    """Official NVD CVSS v2 base-score formula."""
    av = _V2_WEIGHTS["AV"][parsed.attack_vector]
    ac = _V2_WEIGHTS["AC"][parsed.attack_complexity]
    au = _V2_WEIGHTS["Au"][parsed.authentication]
    c = _V2_WEIGHTS["C"][parsed.confidentiality_impact]
    i = _V2_WEIGHTS["I"][parsed.integrity_impact]
    a = _V2_WEIGHTS["A"][parsed.availability_impact]

    impact = 10.41 * (1 - (1 - c) * (1 - i) * (1 - a))
    exploitability = 20 * av * ac * au
    f_impact = 0.0 if impact == 0 else 1.176
    base_score = ((0.6 * impact) + (0.4 * exploitability) - 1.5) * f_impact
    return round(max(0.0, min(10.0, base_score)), 1)


# --- CVSS v3.0 / v3.1 -----------------------------------------------------

_V3_AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_V3_AC_WEIGHTS = {"L": 0.77, "H": 0.44}
_V3_PR_WEIGHTS_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_V3_PR_WEIGHTS_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_V3_UI_WEIGHTS = {"N": 0.85, "R": 0.62}
_V3_CIA_WEIGHTS = {"N": 0.0, "L": 0.22, "H": 0.56}
_V3_REQUIRED_METRICS: tuple[str, ...] = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


class CvssV3Vector(BaseModel):
    """Parsed CVSS v3.0/3.1 base metrics (e.g.
    `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)."""

    model_config = ConfigDict(frozen=True)

    version: CvssVersion
    attack_vector: str
    attack_complexity: str
    privileges_required: str
    user_interaction: str
    scope: str
    confidentiality_impact: str
    integrity_impact: str
    availability_impact: str


_V3_PREFIX_RE = re.compile(r"^CVSS:(3\.0|3\.1)/")


def parse_cvss_v3_vector(vector: str) -> CvssV3Vector:
    """Parses a `CVSS:3.0/...` or `CVSS:3.1/...` vector string. Raises
    `CVSSVectorParseError` on any malformed or unrecognized component."""
    stripped = vector.strip()
    prefix_match = _V3_PREFIX_RE.match(stripped)
    if prefix_match is None:
        raise CVSSVectorParseError(
            "CVSS v3 vector must start with 'CVSS:3.0/' or 'CVSS:3.1/'.", vector=vector
        )
    version = CvssVersion.V3_0 if prefix_match.group(1) == "3.0" else CvssVersion.V3_1
    remainder = stripped[prefix_match.end() :]

    components: dict[str, str] = {}
    for part in remainder.split("/"):
        if ":" not in part:
            raise CVSSVectorParseError(f"Malformed CVSS v3 metric segment: {part!r}", vector=vector)
        key, _, value = part.partition(":")
        components[key] = value

    for metric in _V3_REQUIRED_METRICS:
        if metric not in components:
            raise CVSSVectorParseError(
                f"Missing required CVSS v3 metric '{metric}'.", vector=vector
            )

    av, ac, pr, ui, scope, c, i, a = (components[m] for m in _V3_REQUIRED_METRICS)
    pr_table = _V3_PR_WEIGHTS_CHANGED if scope == "C" else _V3_PR_WEIGHTS_UNCHANGED
    for value, table, name in (
        (av, _V3_AV_WEIGHTS, "AV"),
        (ac, _V3_AC_WEIGHTS, "AC"),
        (pr, pr_table, "PR"),
        (ui, _V3_UI_WEIGHTS, "UI"),
        (c, _V3_CIA_WEIGHTS, "C"),
        (i, _V3_CIA_WEIGHTS, "I"),
        (a, _V3_CIA_WEIGHTS, "A"),
    ):
        if value not in table:
            raise CVSSVectorParseError(
                f"Unrecognized value '{value}' for CVSS v3 metric '{name}'.", vector=vector
            )
    if scope not in ("U", "C"):
        raise CVSSVectorParseError(
            f"Unrecognized value '{scope}' for CVSS v3 metric 'S'.", vector=vector
        )

    return CvssV3Vector(
        version=version,
        attack_vector=av,
        attack_complexity=ac,
        privileges_required=pr,
        user_interaction=ui,
        scope=scope,
        confidentiality_impact=c,
        integrity_impact=i,
        availability_impact=a,
    )


def calculate_cvss_v3_base_score(parsed: CvssV3Vector) -> float:
    """Official FIRST CVSS v3.1 base-score formula, applied identically for
    v3.0 (the base-metric weights are unchanged between the two; only the
    "Roundup" tie-breaking algorithm differs at the edge, which this module
    does not distinguish — a documented, minor simplification)."""
    scope_changed = parsed.scope == "C"
    pr_table = _V3_PR_WEIGHTS_CHANGED if scope_changed else _V3_PR_WEIGHTS_UNCHANGED

    av = _V3_AV_WEIGHTS[parsed.attack_vector]
    ac = _V3_AC_WEIGHTS[parsed.attack_complexity]
    pr = pr_table[parsed.privileges_required]
    ui = _V3_UI_WEIGHTS[parsed.user_interaction]
    c = _V3_CIA_WEIGHTS[parsed.confidentiality_impact]
    i = _V3_CIA_WEIGHTS[parsed.integrity_impact]
    a = _V3_CIA_WEIGHTS[parsed.availability_impact]

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    combined = impact + exploitability
    base_score = _cvss_roundup(min(1.08 * combined, 10.0) if scope_changed else min(combined, 10.0))
    return round(max(0.0, min(10.0, base_score)), 1)


# --- CVSS v4.0 (vector validation only — see module docstring) -----------

_V4_REQUIRED_METRICS: tuple[str, ...] = (
    "AV",
    "AC",
    "AT",
    "PR",
    "UI",
    "VC",
    "VI",
    "VA",
    "SC",
    "SI",
    "SA",
)
_V4_METRIC_VALUES: dict[str, set[str]] = {
    "AV": {"N", "A", "L", "P"},
    "AC": {"L", "H"},
    "AT": {"N", "P"},
    "PR": {"N", "L", "H"},
    "UI": {"N", "P", "A"},
    "VC": {"H", "L", "N"},
    "VI": {"H", "L", "N"},
    "VA": {"H", "L", "N"},
    "SC": {"H", "L", "N"},
    "SI": {"H", "L", "N"},
    "SA": {"H", "L", "N"},
}
_V4_PREFIX = "CVSS:4.0/"


def validate_cvss_v4_vector(vector: str) -> None:
    """Structural/format validation only for CVSS v4.0 vectors (see module
    docstring: base-score computation from a v4.0 vector is out of scope).
    Raises `CVSSVectorParseError` if the vector is malformed; returns `None`
    on success."""
    stripped = vector.strip()
    if not stripped.startswith(_V4_PREFIX):
        raise CVSSVectorParseError("CVSS v4 vector must start with 'CVSS:4.0/'.", vector=vector)

    components: dict[str, str] = {}
    for part in stripped[len(_V4_PREFIX) :].split("/"):
        if not part:
            continue
        if ":" not in part:
            raise CVSSVectorParseError(f"Malformed CVSS v4 metric segment: {part!r}", vector=vector)
        key, _, value = part.partition(":")
        components[key] = value

    for metric in _V4_REQUIRED_METRICS:
        if metric not in components:
            raise CVSSVectorParseError(
                f"Missing required CVSS v4 metric '{metric}'.", vector=vector
            )
        if components[metric] not in _V4_METRIC_VALUES[metric]:
            raise CVSSVectorParseError(
                f"Unrecognized value '{components[metric]}' for CVSS v4 metric '{metric}'.",
                vector=vector,
            )


# --- Unified dispatch ------------------------------------------------------


class ParsedCvssVector(BaseModel):
    """Unified result of `parse_cvss_vector` — `base_score` is populated for
    v2/v3.x, left `None` for v4.0 (see module docstring)."""

    model_config = ConfigDict(frozen=True)

    version: CvssVersion
    vector: str
    base_score: float | None = None


class CvssCalculator:
    """Stateless facade over this module's version-specific parsers/
    formulas — the one entry point `core/vulnerabilities` and any future
    caller uses, so a new CVSS version's dispatch logic lives in exactly
    one place."""

    #: Versions with a closed-form base-score formula this module computes.
    SCORABLE_VERSIONS: ClassVar[frozenset[CvssVersion]] = frozenset(
        {CvssVersion.V2, CvssVersion.V3_0, CvssVersion.V3_1}
    )

    def parse(self, vector: str) -> ParsedCvssVector:
        """Detects the CVSS version from the vector's own prefix (or its
        bare-metric shape for v2, which has no prefix) and dispatches to the
        matching parser/formula. Raises `CVSSVectorParseError` for anything
        unrecognized."""
        stripped = vector.strip()
        if stripped.startswith("CVSS:4.0/"):
            validate_cvss_v4_vector(stripped)
            return ParsedCvssVector(version=CvssVersion.V4_0, vector=stripped, base_score=None)
        if stripped.startswith(("CVSS:3.1/", "CVSS:3.0/")):
            parsed_v3 = parse_cvss_v3_vector(stripped)
            return ParsedCvssVector(
                version=parsed_v3.version,
                vector=stripped,
                base_score=calculate_cvss_v3_base_score(parsed_v3),
            )
        parsed_v2 = parse_cvss_v2_vector(stripped)
        return ParsedCvssVector(
            version=CvssVersion.V2,
            vector=stripped,
            base_score=calculate_cvss_v2_base_score(parsed_v2),
        )

    def score(self, vector: str) -> CvssScore:
        """Parses and classifies severity in one call — the convenience
        entry point most callers actually want."""
        parsed = self.parse(vector)
        severity = (
            classify_cvss_severity(parsed.base_score)
            if parsed.base_score is not None
            else CvssSeverity.INFO
        )
        return CvssScore(
            version=parsed.version,
            vector=parsed.vector,
            base_score=parsed.base_score,
            severity=severity,
        )
