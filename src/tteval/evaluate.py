"""Score TenantTrace against the corpus ground truth.

For every scenario: generate the exports, run ingest, coverage, analysis and (optionally) the
report, then compare with ground_truth.json:

  findings   each expected (rule, attack step) pair is detected when a finding of that rule cites
             at least one of the step's records. Findings in attack cases that cite attack records
             but no enumerated step count as "related"; findings citing no attack record are false
             positives. In benign cases a finding is a false positive unless the ground truth
             allows that rule at that level or below.
  capability rules the ground truth says cannot be assessed must be reported as not assessable.
  gaps       expected gaps must be reported; any other gap is unexpected.
  pivot      expected accounts must appear in the pivot; other accounts listed are extra.
"""

from __future__ import annotations

import argparse
import json
import shutil
import time
from pathlib import Path
from typing import Any

from tenanttrace import __version__
from tenanttrace.case import Case
from tenanttrace.pipeline import analyze, coverage, ingest, report, tool_versions
from tenanttrace.store import CaseStore
from ttcorpus.generate import generate, list_scenarios

LEVEL_RANK = {"possible": 1, "probable": 2, "confirmed": 3}


def _gap_matches(gap: dict[str, Any], want: dict[str, Any]) -> bool:
    if gap["kind"] != want["kind"]:
        return False
    if gap["source"] != want["source"] and want["source"] not in (gap.get("affects_sources") or []):
        return False
    if want.get("cause_contains"):
        return want["cause_contains"] in gap["statement"] + " " + " ".join(gap["likely_causes"])
    return True


def score_scenario(gt: dict[str, Any], case: Case) -> dict[str, Any]:
    analysis = case.read_json("analysis.json") or {}
    cov = case.read_json("coverage.json") or {}
    findings = analysis.get("findings", [])
    with CaseStore(case.db_path) as store:
        rec_of = {}
        for f in findings:
            for eid in f["event_ids"]:
                if eid not in rec_of:
                    ev = store.event(eid)
                    rec_of[eid] = ev.record_id if ev else ""
    step_records = {s["id"]: {r["id"] for r in s["records"] if r["exported"]} for s in gt["steps"]}
    attack_records = set()
    for s in gt["steps"]:
        if s.get("actor_kind") == "attacker":
            attack_records |= step_records[s["id"]]

    def cites(f: dict[str, Any], recs: set[str]) -> bool:
        return any(rec_of.get(e) in recs for e in f["event_ids"])

    expected_rows = []
    for exp in gt["expected_findings"]:
        hits = [f for f in findings if f["rule_id"] == exp["rule"] and cites(f, step_records.get(exp["truth_id"], set()))]
        expected_rows.append({**exp, "detected": bool(hits),
                              "level": max((f["level"] for f in hits), key=lambda lv: LEVEL_RANK[lv], default=None)})
    matched_ids = {f["id"] for f in findings for exp in gt["expected_findings"]
                   if f["rule_id"] == exp["rule"] and cites(f, step_records.get(exp["truth_id"], set()))}
    false_pos, related, allowed = [], [], []
    for f in findings:
        if f["id"] in matched_ids:
            continue
        if gt["kind"] == "benign":
            ok = any(a["rule"] == f["rule_id"] and LEVEL_RANK[f["level"]] <= LEVEL_RANK[a["max_confidence"]]
                     for a in gt.get("allowed_findings", []))
            (allowed if ok else false_pos).append(f)
        elif cites(f, attack_records):
            related.append(f)
        else:
            false_pos.append(f)
    cap = {c["rule_id"]: c for c in analysis.get("capability", [])}
    na_rows = [{"rule": r, "reported": cap.get(r, {}).get("status") == "not_assessable",
                "reason": "; ".join(cap.get(r, {}).get("reasons", []))} for r in gt.get("expected_not_assessable", [])]
    gaps = cov.get("gaps", [])
    gap_rows = [{**w, "reported": any(_gap_matches(g, w) for g in gaps)} for w in gt.get("expected_gaps", [])]
    unexpected_gaps = [g for g in gaps if not any(_gap_matches(g, w) for w in gt.get("expected_gaps", []))]
    pivot_accounts = [p["account"] for p in analysis.get("pivot", [])]
    pivot_rows = [{"account": a, "found": a in pivot_accounts} for a in gt.get("expected_pivot", [])]
    extra_pivot = [a for a in pivot_accounts if a not in gt.get("expected_pivot", [])]
    return {
        "scenario": gt["scenario"],
        "kind": gt["kind"],
        "title": gt["title"],
        "window": analysis.get("window", {}),
        "expected_findings": expected_rows,
        "false_positives": [{"rule": f["rule_id"], "level": f["level"], "summary": f["summary"]} for f in false_pos],
        "related_findings": [{"rule": f["rule_id"], "level": f["level"], "summary": f["summary"]} for f in related],
        "allowed_findings": [{"rule": f["rule_id"], "level": f["level"], "summary": f["summary"]} for f in allowed],
        "not_assessable": na_rows,
        "gaps": gap_rows,
        "unexpected_gaps": [{"kind": g["kind"], "source": g["source"], "statement": g["statement"]} for g in unexpected_gaps],
        "pivot": pivot_rows,
        "extra_pivot": extra_pivot,
        "findings_total": len(findings),
    }


def run(work: Path, scenarios: list[str] | None = None, with_report: bool = False, quiet: bool = True) -> dict[str, Any]:
    work = Path(work)
    corpus = work / "corpus"
    cases = work / "cases"
    if corpus.exists():
        shutil.rmtree(corpus)
    corpus.mkdir(parents=True)
    cases.mkdir(parents=True, exist_ok=True)
    results = []
    for sid in scenarios or list_scenarios():
        t0 = time.perf_counter()
        gt = generate(sid, corpus)
        case = Case(cases / sid, echo=not quiet)
        ingest(corpus / sid / "exports", case, force=True)
        coverage(case, user=gt["primary_user"], collected_at=gt["collected_at"],
                 window_start=gt.get("window_start"))
        analyze(case)
        if with_report:
            report(case, pdf=False)
        res = score_scenario(gt, case)
        res["seconds"] = round(time.perf_counter() - t0, 2)
        results.append(res)
    summary = summarise(results)
    out = {"tool_version": __version__, "versions": tool_versions(), "summary": summary, "scenarios": results}
    (work / "results.json").write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (work / "results.md").write_text(render_markdown(out), encoding="utf-8")
    return out


def summarise(results: list[dict[str, Any]]) -> dict[str, Any]:
    exp = [e for r in results for e in r["expected_findings"]]
    na = [n for r in results for n in r["not_assessable"]]
    gaps = [g for r in results for g in r["gaps"]]
    piv = [p for r in results for p in r["pivot"]]
    benign = [r for r in results if r["kind"] == "benign"]
    return {
        "scenarios": len(results),
        "expected_findings": len(exp),
        "expected_findings_detected": sum(e["detected"] for e in exp),
        "false_positives_attack_and_degraded": sum(len(r["false_positives"]) for r in results if r["kind"] != "benign"),
        "false_positives_benign": sum(len(r["false_positives"]) for r in benign),
        "allowed_benign_findings": sum(len(r["allowed_findings"]) for r in benign),
        "related_findings": sum(len(r["related_findings"]) for r in results),
        "not_assessable_expected": len(na),
        "not_assessable_reported": sum(n["reported"] for n in na),
        "gaps_expected": len(gaps),
        "gaps_reported": sum(g["reported"] for g in gaps),
        "unexpected_gaps": sum(len(r["unexpected_gaps"]) for r in results),
        "pivot_expected": len(piv),
        "pivot_found": sum(p["found"] for p in piv),
        "pivot_extra": sum(len(r["extra_pivot"]) for r in results),
    }


def render_markdown(out: dict[str, Any]) -> str:
    s = out["summary"]
    v = out["versions"]
    lines = [
        "# TenantTrace evaluation results",
        "",
        f"Tool {v['tool']}, rule set {v['ruleset']}, reference table {v['reference_table']}.",
        "",
        "These results come from synthetic exports generated from documented layouts. They show that the",
        "implementation matches its specification on that data; they are not a measure of how the tool",
        "performs on real incidents.",
        "",
        "## Summary",
        "",
        "| Measure | Result |",
        "|---|---|",
        f"| Scenarios | {s['scenarios']} |",
        f"| Expected findings detected | {s['expected_findings_detected']} / {s['expected_findings']} |",
        f"| False positives in attack and degraded cases | {s['false_positives_attack_and_degraded']} |",
        f"| False positives in benign cases | {s['false_positives_benign']} |",
        f"| Benign findings within their allowed level (possible) | {s['allowed_benign_findings']} |",
        f"| Additional findings citing attack records | {s['related_findings']} |",
        f"| Rules correctly reported as not assessable | {s['not_assessable_reported']} / {s['not_assessable_expected']} |",
        f"| Expected evidence gaps reported | {s['gaps_reported']} / {s['gaps_expected']} |",
        f"| Unexpected evidence gaps | {s['unexpected_gaps']} |",
        f"| Expected pivot accounts found | {s['pivot_found']} / {s['pivot_expected']} |",
        f"| Extra pivot accounts | {s['pivot_extra']} |",
        "",
        "## Per scenario",
        "",
        "| Scenario | Kind | Findings detected | FP | Not assessable | Gaps | Pivot | Extra pivot | Seconds |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for r in out["scenarios"]:
        ef = r["expected_findings"]
        lines.append(
            f"| {r['scenario']} | {r['kind']} | {sum(e['detected'] for e in ef)}/{len(ef)} | {len(r['false_positives'])} | "
            f"{sum(n['reported'] for n in r['not_assessable'])}/{len(r['not_assessable'])} | "
            f"{sum(g['reported'] for g in r['gaps'])}/{len(r['gaps'])}"
            f"{' +' + str(len(r['unexpected_gaps'])) if r['unexpected_gaps'] else ''} | "
            f"{sum(p['found'] for p in r['pivot'])}/{len(r['pivot'])} | {len(r['extra_pivot'])} | {r['seconds']} |")
    lines += ["", "## Details", ""]
    for r in out["scenarios"]:
        lines.append(f"### {r['scenario']}")
        lines.append("")
        lines.append(f"{r['title']}. Window: {r['window'].get('start', '')} ({r['window'].get('method', '')}).")
        lines.append("")
        for e in r["expected_findings"]:
            lines.append(f"- {'detected' if e['detected'] else 'MISSED'}: {e['rule']} for step `{e['truth_id']}`"
                         + (f" ({e['level']})" if e["level"] else ""))
        for f in r["false_positives"]:
            lines.append(f"- false positive: {f['rule']} ({f['level']}): {f['summary']}")
        for f in r["allowed_findings"]:
            lines.append(f"- allowed benign finding: {f['rule']} ({f['level']}): {f['summary']}")
        for f in r["related_findings"]:
            lines.append(f"- additional finding on attack records: {f['rule']} ({f['level']}): {f['summary']}")
        for n in r["not_assessable"]:
            lines.append(f"- {'reported' if n['reported'] else 'NOT REPORTED'} as not assessable: {n['rule']}"
                         + (f" ({n['reason']})" if n["reason"] else ""))
        for g in r["gaps"]:
            lines.append(f"- {'reported' if g['reported'] else 'MISSED'} gap: {g['kind']} in {g['source']}")
        for g in r["unexpected_gaps"]:
            lines.append(f"- unexpected gap: {g['kind']} in {g['source']}: {g['statement']}")
        for p in r["pivot"]:
            lines.append(f"- pivot {'found' if p['found'] else 'MISSED'}: {p['account']}")
        for a in r["extra_pivot"]:
            lines.append(f"- extra pivot account: {a}")
        lines.append("")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    from tenanttrace import netguard

    netguard.install()
    ap = argparse.ArgumentParser(prog="tteval", description="Score TenantTrace against the synthetic corpus")
    ap.add_argument("--work", type=Path, default=Path("eval") / "work")
    ap.add_argument("--out", type=Path, default=Path("eval"), help="where results.md and results.json are copied")
    ap.add_argument("--report", action="store_true", help="also render each case's HTML/JSON report")
    ap.add_argument("scenarios", nargs="*")
    args = ap.parse_args(argv)
    out = run(args.work, args.scenarios or None, with_report=args.report)
    args.out.mkdir(parents=True, exist_ok=True)
    for name in ("results.md", "results.json"):
        if (args.work / name).resolve() != (args.out / name).resolve():
            shutil.copy(args.work / name, args.out / name)
    print(json.dumps(out["summary"], indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
