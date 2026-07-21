"""`ResponseValidator` — the task's named "Response Validator".

Runs after `CitationEngine` has already attached citations, and checks the
*pair* (`ChatCompletion`, attached citations) against the case's actually
retrieved evidence for the properties constitution §10 ("output validation")
and this task both require of anything an LLM-shaped component emits:

- grounded in retrieved data (no source id the completion claims that
  wasn't actually retrieved — see `ResponseValidationResult.grounded`),
- carries citations whenever there was evidence available to cite,
- degrades gracefully rather than silently when a check fails.

This does not re-implement anything `CitationEngine` already does (it never
drops or invents a citation itself) — it makes that class's existing
grounding guarantee an explicit, independently testable, auditable unit
instead of an implicit side effect a reviewer has to infer by reading
`CitationEngine`'s internals (constitution §1.3).

Semantic checks this module does *not* attempt (a documented, honest scope
boundary, matching `RetrievalLayer`'s own disclosed keyword-overlap-only
boundary): whether the answer's *prose* is factually consistent with the
cited evidence, or whether a specific recommendation is individually
substantiated. With `TemplateChatModelProvider` as the only implemented
provider, the answer text is structurally templated from retrieved items
alone, so the citation/grounding check below is a sound proxy today; a
future free-text-generating `ChatModelProvider` would need this module
extended with real claim-level checking before being trusted, not silently
assumed safe.
"""

from __future__ import annotations

from core.conversation.models import ChatCompletion, ResponseValidationResult, RetrievedItem


class ResponseValidator:
    """Stateless: a pure function over a completion, its available items,
    and its already-attached citation count."""

    def validate(
        self,
        completion: ChatCompletion,
        *,
        available_items: list[RetrievedItem],
        citation_count: int,
    ) -> ResponseValidationResult:
        known_source_ids = {item.source_id for item in available_items}
        hallucinated = tuple(
            source_id
            for source_id in dict.fromkeys(completion.used_source_ids)
            if source_id not in known_source_ids
        )
        grounded = not hallucinated
        has_citations = citation_count > 0

        issues: list[str] = []
        if not grounded:
            issues.append(
                "completion claimed source id(s) that were never retrieved: "
                + ", ".join(hallucinated)
            )
        if available_items and not has_citations:
            issues.append("evidence was available but the answer carries no citations")

        return ResponseValidationResult(
            grounded=grounded,
            hallucinated_source_ids=hallucinated,
            has_citations=has_citations,
            issues=tuple(issues),
        )
