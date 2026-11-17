# Progress

Resume here after a context reset: read this file, then `git log --oneline`.

## Phase checklist

- [x] 1. Skeleton: package, CLI, case folder, hashing and manifest, processing log, event schema, SQLite store, CI
- [x] 2. Formats and corpus
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

- Phase 2: research notes in docs/sources/ (formats, retention and licensing, collectors, ATT&CK,
  third-party samples). `ttcorpus` generates 11 scenarios (4 attack, 3 benign, 4 degraded) in 7
  export layouts with ground truth. tests/test_corpus_layouts.py checks every generated file
  against docs/sources/layouts.yaml field for field (headers, AuditData keys per record type,
  Graph sign-in keys), record counts, documentation-only IPs and domains, and that the generator
  never imports tenanttrace.

## Next

- Phase 3: format detection and parsers (Purview CSV both layouts, PowerShell CSV, UAL JSON,
  Entra CSV and JSON, Extractor Suite layout), cross-log linking, raw pointers.

## Drafted ahead (uncommitted until their phase)

- Rule engine, rule YAML files, baseline, pivot, timeline, coverage analysis and the gap
  reference table were drafted while research ran; they are committed with phases 4 to 6.

## Environment notes

- The `python` on PATH is a 32-bit 3.12. The project venv is built from the 64-bit 3.12 via `py -3.12 -m venv .venv`.
- No git remote is configured; commits are local only.
