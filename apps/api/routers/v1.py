"""Aggregator for every versioned domain route (``/api/v1/...``).

Empty at the foundation stage — no domain resources (Case, Evidence,
Finding, Report) exist yet (docs/roadmap.md Milestone M1+). Future routers
register here via ``api_v1_router.include_router(...)``:

    from apps.api.routers import cases
    api_v1_router.include_router(cases.router)

context/03_engineering_constitution.md §6: all versioned resource routes
mount under this one prefix so a future breaking change gets its own
``/api/v2`` aggregator instead of mutating this one in place.
"""

from __future__ import annotations

from fastapi import APIRouter

api_v1_router = APIRouter(prefix="/api/v1")
