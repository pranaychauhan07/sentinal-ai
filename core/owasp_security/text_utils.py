"""Shared text-sanitization helper for `core/owasp_security` — deliberately
its own tiny module so both the per-finding snippet builders
(`python_ast_analyzer.py`/`pattern_analyzer.py`) and the top-level
orchestrator (`analysis_engine.py`) can import it without a circular
dependency (`analysis_engine.py` imports `vulnerability_detection_engine.py`,
which imports the two analyzer modules).
"""

from __future__ import annotations

import re

#: Strips ASCII control characters (including embedded CR/LF) from a short
#: extracted code snippet before it is logged or surfaced in advice text —
#: the log-injection guard (constitution §10). Applied only to individual
#: snippets, never to a whole multi-line source file (which would destroy
#: its newline structure before AST parsing).
_CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def sanitize_snippet(text: str) -> str:
    collapsed = text.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    return _CONTROL_CHAR_PATTERN.sub("", collapsed)
