#!/usr/bin/env python3
"""Static enforcement of the ADR-0002 rule: `core/` must never import
`streamlit` or `fastapi` (docs/dependency-rules.md, rule 1).

Run via pre-commit and CI (.github/workflows/ci.yml). Exits non-zero and
prints every offending file/import if the rule is violated.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

FORBIDDEN_TOP_LEVEL_IMPORTS = {"streamlit", "fastapi"}
CORE_ROOT = Path(__file__).resolve().parent.parent / "core"


def _imported_top_level_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
    return names


def find_violations(core_root: Path) -> list[tuple[Path, str]]:
    violations: list[tuple[Path, str]] = []
    for path in sorted(core_root.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError as exc:
            violations.append((path, f"failed to parse: {exc}"))
            continue
        for name in _imported_top_level_names(tree) & FORBIDDEN_TOP_LEVEL_IMPORTS:
            violations.append((path, f"imports forbidden module '{name}'"))
    return violations


def main() -> int:
    if not CORE_ROOT.is_dir():
        print(f"core/ directory not found at {CORE_ROOT}", file=sys.stderr)
        return 1

    violations = find_violations(CORE_ROOT)
    if not violations:
        print("OK: core/ contains no streamlit/fastapi imports.")
        return 0

    print("Dependency rule violation(s) found (docs/dependency-rules.md, rule 1):\n")
    for path, reason in violations:
        print(f"  {path.relative_to(CORE_ROOT.parent)}: {reason}")
    print(f"\n{len(violations)} violation(s). See docs/dependency-rules.md.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
