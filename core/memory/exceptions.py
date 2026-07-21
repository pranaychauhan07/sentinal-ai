"""Narrow exception hierarchy for `core/memory` (ADR-0027), mirroring
`core/conversation/exceptions.py`'s/`core/incident_response/exceptions.py`'s
established pattern (constitution §5: "every tool module defines its own
narrow exception classes").

Every one of these is caught at the point of use (`long_term.py`,
`manager.py`) and converted into a degraded-but-correct outcome — per
ADR-0006, long-term memory is always advisory, so none of these exceptions
is ever allowed to propagate out of the memory layer to a caller.
"""

from __future__ import annotations

from core.exceptions import ValidationError


class MemoryLayerError(ValidationError):
    """Base class for every exception this package raises deliberately."""

    code = "MEMORY_ERROR"


class InvalidEmbeddingError(MemoryLayerError):
    """An embedding vector is empty, contains a non-finite value, or has an
    inconsistent dimension for its target collection — rejected before it
    ever reaches a vector-store write."""

    code = "INVALID_EMBEDDING"


class EmbeddingProviderError(MemoryLayerError):
    """A concrete `TextEmbedder` (`core/memory/embedding_providers.py`)
    failed to reach or was rejected by its backing provider (missing
    credentials, network failure, rate limit). Always caught by
    `long_term.py`'s advisory boundary — never raised to a caller."""

    code = "EMBEDDING_PROVIDER_ERROR"


class VectorStoreError(MemoryLayerError):
    """A concrete `VectorMemory` backend (`chroma_vector_store.py`) failed
    to complete a read/write operation."""

    code = "VECTOR_STORE_ERROR"
