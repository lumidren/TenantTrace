"""The whole corpus scores perfectly against its ground truth (generated data only)."""

from __future__ import annotations

from tteval.evaluate import run


def test_corpus_evaluation(tmp_path):
    out = run(tmp_path / "eval")
    s = out["summary"]
    assert s["expected_findings_detected"] == s["expected_findings"] > 40
    assert s["false_positives_attack_and_degraded"] == 0
    assert s["false_positives_benign"] == 0
    assert s["not_assessable_reported"] == s["not_assessable_expected"]
    assert s["gaps_reported"] == s["gaps_expected"] and s["unexpected_gaps"] == 0
    assert s["pivot_found"] == s["pivot_expected"] and s["pivot_extra"] == 0
    assert (tmp_path / "eval" / "results.md").read_text(encoding="utf-8").startswith("# TenantTrace evaluation")
