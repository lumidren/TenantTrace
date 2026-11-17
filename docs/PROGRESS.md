# Progress

Resume here after a context reset: read this file, then `git log --oneline`.

## Phase checklist

- [x] 1. Skeleton: package, CLI, case folder, hashing and manifest, processing log, event schema, SQLite store, CI
- [ ] 2. Formats and corpus
- [ ] 3. Parsers and normalization
- [ ] 4. Evidence gap analysis
- [ ] 5. Detection
- [ ] 6. Timeline and pivot
- [ ] 7. Report
- [ ] 8. Evaluation and ship

## Verified

- Phase 1: `tenanttrace run` on an empty folder produces a case folder with `manifest.json`,
  `processing.log`, `case.sqlite` and `report/report.json`; inputs are hashed and unchanged
  (hash and mtime) after ingest; the network guard blocks sockets (tests/test_skeleton.py).

## Next

- Phase 2: confirm formats (research notes under docs/sources/), scenario generator, corpus.

## Environment notes

- The `python` on PATH is a 32-bit 3.12. The project venv is built from the 64-bit 3.12 via `py -3.12 -m venv .venv`.
- No git remote is configured; commits are local only.
