# evidence_uploads — Content-Addressed Raw Evidence Storage

**Purpose:** Local filesystem storage for uploaded evidence artifacts,
written by `core/services/evidence_service.py::EvidencePipeline._store_raw_content`.

**Layout:** One file per unique upload, named `<sha256>.<original-extension>`
— content-addressed and idempotent, so re-uploading identical bytes never
duplicates the blob. `core.db.models.evidence.Evidence.storage_ref` points
here.

**Not committed:** every file in this directory except this README and
`.gitkeep` is gitignored (`.gitignore`'s "Runtime artifacts" section) — this
is local/dev storage, not a durable evidence store. A future object-store
swap (S3/Azure Blob) replaces only `_store_raw_content`'s implementation;
`storage_ref` stays an opaque string to every other caller.
