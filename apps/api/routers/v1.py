"""Aggregator for every versioned domain route (``/api/v1/...``).

context/03_engineering_constitution.md §6: all versioned resource routes
mount under this one prefix so a future breaking change gets its own
``/api/v2`` aggregator instead of mutating this one in place.
"""

from __future__ import annotations

from fastapi import APIRouter

from apps.api.routers import cases, evidence, findings, iocs

api_v1_router = APIRouter(prefix="/api/v1")
api_v1_router.include_router(cases.router)
api_v1_router.include_router(evidence.router)
api_v1_router.include_router(iocs.router)
api_v1_router.include_router(findings.router)
