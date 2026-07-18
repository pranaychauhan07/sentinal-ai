# ADR-0005: ChromaDB as the Long-Term Memory Vector Store

**Status:** Accepted
**Date:** 2026-07-18

## Purpose

The Memory Agent needs to answer "has this IOC/pattern appeared in a past
case?" via semantic similarity over embedded findings — a capability
relational SQL cannot provide directly. We needed a vector store decision
before implementing `core/memory/long_term.py`.

## Decision

Use ChromaDB as the sole vector store, holding one collection
(`case_findings_embeddings`) keyed by `finding_id`/`case_id`, always
treated as a retrieval-only cache — PostgreSQL remains authoritative (see
ADR-0004). See `context/01_blueprint.md` §8.

## Alternatives Considered

- **FAISS** (also named in the capstone spec) — a library, not a service;
  would require hand-rolling persistence, metadata filtering, and a query
  API that ChromaDB already provides out of the box. Rejected in favor of
  less custom infrastructure code for the same result.
- **pgvector extension on the existing PostgreSQL instance** — would avoid
  running a second service, and is a reasonable future consolidation.
  Rejected for now specifically because ChromaDB's independent
  availability is what makes "memory retrieval is always optional/advisory"
  (blueprint §7, Memory Agent — Failure handling) a clean architectural
  boundary: if vector search lived inside the same Postgres instance as the
  system of record, a memory-layer outage and a system-of-record outage
  would no longer be independent failure modes.
- **Pinecone/Weaviate (hosted vector DBs)** — introduces an external network
  dependency and cost for a capability that's genuinely optional; rejected
  to keep the project fully self-hostable per blueprint §2 (offline-capable
  goal).

## Consequences

- **Positive:** memory is cleanly separable — deleting the ChromaDB
  container has zero effect on case investigation correctness, only on
  cross-case learning quality; self-hostable, no external dependency.
- **Negative:** running a second stateful service in `docker-compose.yml`;
  accepted since it's a single extra container with a documented health
  check and its own volume.
