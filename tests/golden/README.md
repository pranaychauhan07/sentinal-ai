# golden — Report Snapshot Tests

Committed "expected" PDF/report artifacts (or their extracted text/structure)
that generated output is diffed against. A failing golden test means either a
real regression or an intentional template change — in the latter case the
snapshot is regenerated and reviewed in the PR diff, never silently
overwritten.
