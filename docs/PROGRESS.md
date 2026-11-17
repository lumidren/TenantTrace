# Progress

Resume here after a context reset: read this file, then `git log --oneline`.

## Phase checklist

- [x] 1. Skeleton: package, CLI, case folder, hashing and manifest, processing log, event schema, SQLite store, CI
- [x] 2. Formats and corpus
- [x] 3. Parsers and normalization
- [x] 4. Evidence gap analysis
- [x] 5. Detection
- [x] 6. Timeline and pivot
- [x] 7. Report
- [x] 8. Evaluation and ship

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

- Phase 5: rule engine (match, threshold, deviation, sequence, travel), 18 rule files with
  why/benign/sources/confidence/ATT&CK, account baseline, two-stage evaluation, per-rule
  capability check whose results go into coverage.json. tests/test_rules.py has a positive and a
  negative case for every rule, checks ATT&CK IDs against docs/sources/attack-techniques.md, and
  checks that a missing source, absent auditing, a short history or missing coordinates give
  "could not be assessed". `tteval` on the 12 scenarios: 52/52 expected findings, 0 false positives
  (attack, degraded and benign), 8 benign findings all at "possible" within their allowed rules,
  10/10 rules correctly not assessable, 10/10 gaps, 12/12 pivot accounts, 0 extra.
  tests/test_determinism.py (two runs identical) and tests/test_network.py (full run, no socket).

- Phase 6: the demo timeline reads AiTM sign-in (Dallas) -> session replay from Amsterdam
  (inference with basis) -> MFA registration -> hiding inbox rule -> mailbox access -> bulk download
  -> anonymous links -> internal phishing -> return visit -> deleted sent items. Post-compromise
  steps link to the attacker's sign-in by recorded token ID (observed). tests/test_timeline.py:
  order, labels, basis on every inference, a copy of the demo with session IDs stripped falls back to
  IP-and-time links labelled as inferences (and the hiding rule drops from confirmed to probable),
  the pivot lists exactly the second victim (demo), the three spray targets (legacy case) and the
  second consenting user (OAuth case).

- Phase 7: report.json (the export), self-contained report.html (Vite + TypeScript template
  committed at src/tenanttrace/report/template.html, CSP forbids all connections) and report.pdf
  (fpdf2). Executive summary, coverage chart with one lane per source, gaps shaded and labelled,
  detections overlaid; filterable timeline with observed/inference styling; finding drawer with
  evidence; raw-record view re-verified against the ingest hash; gaps, capability, pivot, inputs
  and hashes, method; light/dark/print. tests/test_report.py (7 tests). Browser check:
  scripts/verify_report_browser.mjs opened the demo report from file:// in the installed Edge
  with name resolution and proxying disabled, clicked a coverage marker, the finding's evidence
  row, and saw the raw record with "SHA-256 matches"; Escape closes, Enter opens a focused step;
  zero network requests. Screenshots in docs/screenshots/.
- The PDF layout was checked by text extraction only (no PDF renderer is installed here).

- Phase 8: `tteval` reruns the whole evaluation and rewrites eval/results.md and results.json
  (13 scenarios: 56/56 expected findings, 0 false positives, 16/16 not assessable, 14/14 gaps,
  12/12 pivot accounts). Performance run (scripts/perf_run.py, docs/PERFORMANCE.md): 1,002,149
  records, 115.6 s total, peak 56 MB. Hawk added as the second collector (generator layout, flattened
  CSV parser, per-user scope recognised by the gap analysis). Offline IP database option. Hostile
  input: empty, binary and text files, truncated JSON, malformed rows, UTF-16 without BOM,
  Windows-1252, offsets across the UK clock change, an account absent from every log, a changed
  input at report time. scripts/demo.ps1 ran on a fresh local clone (34 s, venv setup included)
  and a non-editable `pip install .` ran the demo pipeline.

## Status: finished

All eight phases are done; 136 tests pass locally.

## Not verified, or tested on generated data only

- Every detection, gap and pivot result comes from generated data. No real tenant export was
  available; `samples/real/` was empty. docs/VERIFY.md lists the format assumptions to check first.
- The CI workflow (.github/workflows/ci.yml) has never run: there is no git remote, so nothing was
  pushed. Its three jobs (tests on Windows and Linux, template rebuild check, browser click-through)
  were each run locally in equivalent form.
- The PDF was checked by extracting its text (pypdf), not by looking at rendered pages: no PDF
  renderer is installed here and headless Edge does not render PDFs.
- The rebuilt report template was compared only on this Windows machine; the CI job will confirm
  that a Linux build produces the same bytes.
- Hawk and Microsoft-Extractor-Suite layouts were read from their source code, never run.

## Skipped, and why

- Entra audit log CSV download and the sign-in "authentication details" CSVs: their columns are
  undocumented (formats 2a-3, 2c); only the Graph JSON of the audit log is parsed.
- CISA Untitled Goose Tool: a third collector was beyond "a second collector if time allows".
- invictus-ir/o365_dataset (real BEC records): a 7z archive of real incident data that needs
  extraction tools and a privacy review.
- Pushing: no `origin` remote exists; commits are local only.

## Next

1. Run TenantTrace on real exports (Purview CSV, a PowerShell export, the Entra JSON and CSV
   downloads, an Extractor-Suite and a Hawk folder) and work through docs/VERIFY.md.
2. Push to a remote so the CI workflow runs, including the Linux template-equality check.
3. Have an investigator review rule thresholds and confidence criteria against real cases.

## Note on build order

The rule engine, rule files, baseline, pivot, timeline and coverage code were drafted while the
format research ran, but each was committed with its own phase (4 to 6) after that phase's tests
passed.

## Environment notes

- The `python` on PATH is a 32-bit 3.12. The project venv is built from the 64-bit 3.12 via `py -3.12 -m venv .venv`.
- No git remote is configured; commits are local only.
