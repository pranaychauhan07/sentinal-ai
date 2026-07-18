# data — Non-Code Runtime Assets

Two purposes only: `sample_evidence/` (fixtures used for demos, manual testing,
and as pytest fixtures) and `reports_out/` (generated PDF output, gitignored
except for a `.gitkeep`). Nothing under `data/` is imported by application code
— it's read at runtime by path, never `import`ed.
