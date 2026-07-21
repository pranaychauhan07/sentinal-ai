"""Asset Manager — the task's named "Asset Manager".

Turns raw binary assets (an organization logo, a rasterized chart image)
into the form each renderer needs: a `data:` URI for `html_renderer.py`, or
the raw bytes ReportLab's `Image` flowable / python-docx's
`add_picture` accept directly. One place enforces the oversized-asset guard
(constitution §10, "oversized exports") rather than each renderer
reimplementing the same size check.
"""

from __future__ import annotations

import base64

from core.reporting.exceptions import AssetEmbeddingError

#: Ceiling on a single embedded asset (logo or chart image) — a
#: resource-exhaustion guard against an operator accidentally configuring a
#: multi-hundred-megabyte "logo." Generous enough for any legitimate PNG/JPEG
#: logo or a Kaleido-rendered chart at report resolution.
DEFAULT_MAX_ASSET_BYTES = 10 * 1024 * 1024  # 10 MiB

_SUPPORTED_MIME_TYPES = frozenset({"image/png", "image/jpeg", "image/svg+xml"})


class AssetManager:
    def __init__(self, *, max_asset_bytes: int = DEFAULT_MAX_ASSET_BYTES) -> None:
        self._max_asset_bytes = max_asset_bytes

    def _validate(self, data: bytes, *, mime_type: str) -> None:
        if mime_type not in _SUPPORTED_MIME_TYPES:
            raise AssetEmbeddingError(
                f"Unsupported asset MIME type '{mime_type}'.",
                details={"mime_type": mime_type, "supported": sorted(_SUPPORTED_MIME_TYPES)},
            )
        if len(data) > self._max_asset_bytes:
            raise AssetEmbeddingError(
                f"Asset of {len(data)} bytes exceeds the configured maximum of "
                f"{self._max_asset_bytes} bytes.",
                details={"size_bytes": len(data), "max_bytes": self._max_asset_bytes},
            )

    def to_data_uri(self, data: bytes, *, mime_type: str) -> str:
        """HTML export's embedding mechanism — a self-contained `data:` URI,
        never a filesystem/network reference (keeps the exported HTML file
        genuinely portable, matching blueprint §5's offline-capable goal)."""
        self._validate(data, mime_type=mime_type)
        encoded = base64.b64encode(data).decode("ascii")
        return f"data:{mime_type};base64,{encoded}"

    def prepare_binary(self, data: bytes, *, mime_type: str) -> bytes:
        """PDF/DOCX export's embedding mechanism — both ReportLab and
        python-docx accept raw image bytes directly, so this is a validated
        pass-through rather than a transformation; kept as its own method
        (not inlined at each call site) so the size/MIME guard lives in
        exactly one place regardless of which renderer calls it."""
        self._validate(data, mime_type=mime_type)
        return data


def from_data_uri(data_uri: str) -> bytes | None:
    """Inverse of `AssetManager.to_data_uri` — decodes a `data:<mime>;
    base64,<...>` URI (e.g. `ReportTheme.logo_data_uri`) back to raw bytes
    for `pdf_renderer.py`/`docx_renderer.py`, which need a byte stream, not
    a URI. Returns `None` for a malformed/non-base64 URI rather than
    raising — a cosmetic logo failure must never abort a whole export
    (constitution §1.7). A module-level function, not an `AssetManager`
    method, since it needs no size/MIME validation state (the URI was
    already validated when `to_data_uri` produced it)."""
    try:
        _, encoded = data_uri.split(",", 1)
        return base64.b64decode(encoded)
    except (ValueError, TypeError):
        return None
