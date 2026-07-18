#!/usr/bin/env python3
"""Load `data/sample_evidence/` fixtures into the database as demo cases.

This becomes a real seeding routine once `core/db/models.py` and
`core/services/case_service.py` exist (Milestone M1+, see docs/roadmap.md).
Kept as an explicit, documented placeholder rather than silently absent so
`make seed` fails loudly and informatively instead of with an ImportError.
"""

from __future__ import annotations

import sys


def main() -> int:
    print(
        "seed_sample_data.py: no-op placeholder.\n"
        "Implement once core/db/models.py (Case/Evidence/Finding) and "
        "core/services/case_service.py exist — see docs/roadmap.md Milestone M1.\n"
        "Sample fixtures to load are already in data/sample_evidence/ "
        "(see data/sample_evidence/README.md).",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
