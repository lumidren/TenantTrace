"""The same inputs, rule set and reference table always produce the same findings."""

from __future__ import annotations

import json

from tenanttrace.case import Case
from tenanttrace.pipeline import run_all

VOLATILE = {"created_utc", "time_utc", "parse_seconds", "generated_utc", "input_dir", "case_dir", "seconds"}


def _strip(obj):
    if isinstance(obj, dict):
        return {k: _strip(v) for k, v in obj.items() if k not in VOLATILE}
    if isinstance(obj, list):
        return [_strip(v) for v in obj]
    return obj


def test_two_runs_produce_identical_results(corpus_dir, tmp_path):
    src = corpus_dir / "demo_bec" / "exports"
    outs = []
    for name in ("a", "b"):
        case = Case(tmp_path / name)
        run_all(src, case, user="dana.whitfield@harborlane.example", collected_at="2026-11-06T17:00:00Z", pdf=False)
        outs.append({f: _strip(json.loads((case.root / f).read_text(encoding="utf-8")))
                     for f in ("analysis.json", "coverage.json")})
        outs[-1]["manifest_inputs"] = _strip(json.loads((case.root / "manifest.json").read_text(encoding="utf-8"))["inputs"])
    assert outs[0] == outs[1]
    assert outs[0]["analysis.json"]["findings"], "the demo must produce findings for this test to mean anything"
