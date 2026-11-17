# Progress

Resume here after a context reset: read this file, then `git log --oneline`.

## Phase checklist

- [x] 1. Skeleton: package, CLI, case folder, hashing and manifest, processing log, event schema, SQLite store, CI
- [x] 2. Formats and corpus
- [x] 3. Parsers and normalization
- [x] 4. Evidence gap analysis
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

- Phase 3: seven parsers chosen by content (Purview CSV 4- and 8-column, Search-UnifiedAuditLog
  CSV, UAL JSON/JSONL wrapper or AuditData, Entra sign-in CSV, Graph sign-in JSON, Azure Monitor
  sign-ins, Entra directory audit JSON). tests/test_parsers.py: every corpus layout gets the right
  parser and all records; per-file counts reconcile (total = parsed + unrecognised + malformed =
  events stored); every demo event re-reads to its exact source text with a matching SHA-256;
  overlapping exports link as duplicates; UAL sign-in copies corroborate Entra records; malformed
  rows, truncated JSON, empty, binary and text files, UTF-16 without BOM and Windows-1252 inputs;
  the four Splunk real-shape samples parse with no loss.
- Entra audit JSON parsing is tested only through unit-level normalization, not a generated export
  (the corpus has no Entra audit download).

- Phase 4: versioned gap reference table (8 sources, citations, verified flags, export limits);
  coverage per source and container; gaps of kind missing, auditing_absent, truncated, ends_early,
  retention, quiet, user_absent and filtered, each with likely causes and citations.
  tests/test_coverage.py: all five degraded cases report their intended gap and cause (sign-ins
  missing; UAL truncated with the ResultCount evidence and early end; 7-day retention named as
  Microsoft Entra ID Free; mailbox auditing absent with its documented causes; a two-day quiet
  period); the six intact cases report no gaps; the demo reports only its missing non-interactive
  sign-ins; a user absent from every log is reported per source.

## Next

- Phase 5: rule engine, rule files, baseline, per-rule capability check feeding the gap analysis.

## Drafted ahead (uncommitted until their phase)

- Rule engine, rule YAML files, baseline, pivot, timeline, coverage analysis and the gap
  reference table were drafted while research ran; they are committed with phases 4 to 6.

## Environment notes

- The `python` on PATH is a 32-bit 3.12. The project venv is built from the 64-bit 3.12 via `py -3.12 -m venv .venv`.
- No git remote is configured; commits are local only.
