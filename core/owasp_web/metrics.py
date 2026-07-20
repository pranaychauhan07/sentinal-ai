"""``WebSecurityMetricsCollector`` — headers/cookies/JWTs/misconfiguration
candidates analyzed, rule matches by id, processing time, failure counts.
Mirrors `core.linux_advisor.metrics.LinuxAdvisorMetricsCollector`'s
"construct one per process or one per test" shape; self-contained (no
`core/graph` subscription — a leaf must never import `core/graph`).
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class WebSecurityMetricsSnapshot(BaseModel):
    headers_analyzed: int = 0
    cookies_analyzed: int = 0
    jwts_analyzed: int = 0
    misconfiguration_candidates_analyzed: int = 0
    rule_matches_by_id: dict[str, int] = Field(default_factory=dict)
    failure_count: int = 0
    total_processing_ms: float = 0.0


class WebSecurityMetricsCollector:
    def __init__(self) -> None:
        self._headers_analyzed = 0
        self._cookies_analyzed = 0
        self._jwts_analyzed = 0
        self._misconfiguration_candidates_analyzed = 0
        self._rule_matches_by_id: dict[str, int] = {}
        self._failure_count = 0
        self._total_processing_ms = 0.0

    def record_header_analyzed(self) -> None:
        self._headers_analyzed += 1

    def record_cookie_analyzed(self) -> None:
        self._cookies_analyzed += 1

    def record_jwt_analyzed(self) -> None:
        self._jwts_analyzed += 1

    def record_misconfiguration_candidate_analyzed(self) -> None:
        self._misconfiguration_candidates_analyzed += 1

    def record_rule_match(self, rule_id: str) -> None:
        self._rule_matches_by_id[rule_id] = self._rule_matches_by_id.get(rule_id, 0) + 1

    def record_failure(self) -> None:
        self._failure_count += 1

    def record_processing_time(self, duration_ms: float) -> None:
        self._total_processing_ms += duration_ms

    def snapshot(self) -> WebSecurityMetricsSnapshot:
        return WebSecurityMetricsSnapshot(
            headers_analyzed=self._headers_analyzed,
            cookies_analyzed=self._cookies_analyzed,
            jwts_analyzed=self._jwts_analyzed,
            misconfiguration_candidates_analyzed=self._misconfiguration_candidates_analyzed,
            rule_matches_by_id=dict(self._rule_matches_by_id),
            failure_count=self._failure_count,
            total_processing_ms=self._total_processing_ms,
        )
