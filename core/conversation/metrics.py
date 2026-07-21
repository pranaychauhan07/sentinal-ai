"""`ConversationMetricsCollector` — questions answered, retrieval hit/miss,
citations attached, degraded answers, processing time. Mirrors
`core.incident_response.metrics.IncidentResponseMetricsCollector`'s
"construct one per process or one per test" shape; self-contained (no
`core/graph` subscription — a leaf must never import `core/graph`).
"""

from __future__ import annotations

from pydantic import BaseModel


class ConversationMetricsSnapshot(BaseModel):
    questions_answered: int = 0
    retrieval_hits: int = 0
    retrieval_misses: int = 0
    citations_attached: int = 0
    degraded_answers: int = 0
    prompt_injection_flags: int = 0
    validation_failures: int = 0
    total_processing_ms: float = 0.0


class ConversationMetricsCollector:
    def __init__(self) -> None:
        self._questions_answered = 0
        self._retrieval_hits = 0
        self._retrieval_misses = 0
        self._citations_attached = 0
        self._degraded_answers = 0
        self._prompt_injection_flags = 0
        self._validation_failures = 0
        self._total_processing_ms = 0.0

    def record_question_answered(self) -> None:
        self._questions_answered += 1

    def record_retrieval_result(self, *, item_count: int) -> None:
        if item_count > 0:
            self._retrieval_hits += 1
        else:
            self._retrieval_misses += 1

    def record_citations(self, count: int) -> None:
        self._citations_attached += count

    def record_degraded_answer(self) -> None:
        self._degraded_answers += 1

    def record_prompt_injection_flag(self) -> None:
        self._prompt_injection_flags += 1

    def record_validation_failure(self) -> None:
        self._validation_failures += 1

    def record_processing_time(self, duration_ms: float) -> None:
        self._total_processing_ms += duration_ms

    def snapshot(self) -> ConversationMetricsSnapshot:
        return ConversationMetricsSnapshot(
            questions_answered=self._questions_answered,
            retrieval_hits=self._retrieval_hits,
            retrieval_misses=self._retrieval_misses,
            citations_attached=self._citations_attached,
            degraded_answers=self._degraded_answers,
            prompt_injection_flags=self._prompt_injection_flags,
            validation_failures=self._validation_failures,
            total_processing_ms=self._total_processing_ms,
        )
