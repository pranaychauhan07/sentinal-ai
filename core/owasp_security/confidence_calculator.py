"""``calculate_confidence`` — the task's named "Confidence Calculator"
capability: combines a rule's declared base confidence with a
language-support multiplier, a real, documented signal that AST-based
(Python) findings are more reliable than pattern-based (JS/TS/Java)
findings (docs/adr/0021 point 10) — never a single flat number everywhere.
"""

from __future__ import annotations

#: AST-based findings (Python) get no discount — the detection basis is a
#: genuine parse of the code's structure.
AST_BASED_MULTIPLIER = 1.0

#: Pattern-based findings (JavaScript/TypeScript/Java) are discounted —
#: regex/line-based matching has a structurally higher false-positive rate
#: than AST analysis, and this multiplier makes that difference visible to
#: downstream consumers rather than hiding it behind one confidence number.
PATTERN_BASED_MULTIPLIER = 0.75


def calculate_confidence(base_confidence: float, *, is_ast_based: bool) -> float:
    """Returns `base_confidence` scaled by the detection-basis multiplier,
    clamped to `[0.0, 1.0]`."""
    multiplier = AST_BASED_MULTIPLIER if is_ast_based else PATTERN_BASED_MULTIPLIER
    return max(0.0, min(1.0, base_confidence * multiplier))
