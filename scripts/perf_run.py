"""Performance run: a one-million-record unified audit log export through the whole pipeline.

The demo tenant's audit activity is replicated across fictional accounts (perf0001@harborlane.example
and so on) with fresh record IDs, streamed straight to a Purview-layout CSV, and placed next to the
demo's own exports so the analysis of the compromised account runs on top of a large tenant.
Records time and peak memory for each stage and writes docs/PERFORMANCE.md.

    python scripts/perf_run.py [--records 1000000] [--work perf/work]
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import platform
import shutil
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def peak_memory_mb() -> float:
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        class PMC(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                        ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                        ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]

        get_current = ctypes.windll.kernel32.GetCurrentProcess
        get_current.restype = wintypes.HANDLE
        get_info = ctypes.windll.psapi.GetProcessMemoryInfo
        get_info.argtypes = [wintypes.HANDLE, ctypes.POINTER(PMC), wintypes.DWORD]
        get_info.restype = wintypes.BOOL
        pmc = PMC()
        pmc.cb = ctypes.sizeof(PMC)
        if not get_info(get_current(), ctypes.byref(pmc), pmc.cb):
            return float("nan")
        return pmc.PeakWorkingSetSize / 1024 / 1024
    import resource

    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return rss / 1024 if sys.platform != "darwin" else rss / 1024 / 1024


def build_input(work: Path, records: int) -> tuple[Path, dict]:
    from ttcorpus.engine import simulate
    from ttcorpus.generate import generate, load_scenario
    from ttcorpus.writers import PURVIEW_COLUMNS, audit_data, purview_creation_date

    inp = work / "input"
    if inp.exists():
        shutil.rmtree(inp)
    corpus = work / "corpus"
    gt = generate("demo_bec", corpus)
    shutil.copytree(corpus / "demo_bec" / "exports", inp)
    w = simulate(load_scenario("demo_bec"))
    # filler accounts get ordinary activity only: replicating the attacker's records would (correctly)
    # put every filler account into the pivot
    templates = [audit_data(o, w) for o in w.ops if o.tags.get("actor_kind") != "attacker"]
    path = inp / "purview" / "audit_log_search_large.csv"
    n = 0
    copy = 0
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        wr = csv.writer(fh, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
        wr.writerow(PURVIEW_COLUMNS)
        while n < records:
            copy += 1
            user = f"perf{copy:04d}@harborlane.example"
            for ad in templates:
                if n >= records:
                    break
                d = dict(ad)
                d["Id"] = str(uuid.uuid5(uuid.NAMESPACE_OID, f"{copy}:{ad['Id']}"))
                d["UserId"] = user
                if "MailboxOwnerUPN" in d:
                    d["MailboxOwnerUPN"] = user
                d.pop("AppAccessContext", None)
                wr.writerow([d["CreationTime"] + ".0000000Z", user, d["Operation"],
                             json.dumps(d, separators=(",", ":"))])
                n += 1
    _ = purview_creation_date
    return inp, {"records_written": n, "accounts": copy, "file_bytes": path.stat().st_size, "gt": gt}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--records", type=int, default=1_000_000)
    ap.add_argument("--work", type=Path, default=ROOT / "perf" / "work")
    ap.add_argument("--out", type=Path, default=ROOT / "docs" / "PERFORMANCE.md")
    args = ap.parse_args()
    from tenanttrace import netguard
    from tenanttrace.case import Case
    from tenanttrace.pipeline import analyze, coverage, ingest, report

    args.work.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter()
    inp, info = build_input(args.work, args.records)
    t_gen = time.perf_counter() - t0
    netguard.install()
    case = Case(args.work / "case")
    stages = []
    for name, fn in (
        ("ingest", lambda: ingest(inp, case, force=True)),
        ("coverage", lambda: coverage(case, user=info["gt"]["primary_user"], collected_at=info["gt"]["collected_at"])),
        ("analyze", lambda: analyze(case)),
        ("report (HTML, PDF, JSON)", lambda: report(case, pdf=True)),
    ):
        t = time.perf_counter()
        result = fn()
        stages.append({"stage": name, "seconds": round(time.perf_counter() - t, 1), "peak_mb": round(peak_memory_mb())})
        if name == "ingest":
            totals = result["totals"]
        if name == "analyze":
            summary = result["summary"]
    db_mb = case.db_path.stat().st_size / 1024 / 1024
    total = sum(s["seconds"] for s in stages)
    lines = [
        "# Performance",
        "",
        "Measured with `python scripts/perf_run.py` on the machine that built this repository. The input is",
        "synthetic: the demo tenant's audit activity replicated across fictional accounts in one Purview-layout",
        "CSV, next to the demo's own exports. It measures throughput and memory, not detection quality.",
        "",
        f"- Machine: {platform.platform()}, {platform.processor() or platform.machine()}, {os.cpu_count()} logical CPUs",
        f"- Python {platform.python_version()} ({platform.architecture()[0]})",
        f"- Input: {info['records_written']:,} generated audit records for {info['accounts']} accounts in one CSV of "
        f"{info['file_bytes'] / 1024 / 1024:,.0f} MB, plus the demo exports",
        f"- Records ingested: {totals['records_parsed']:,} parsed of {totals['records_total']:,} "
        f"({totals['records_unrecognised']} unrecognised, {totals['records_malformed']} malformed)",
        f"- Case database: {db_mb:,.0f} MB",
        f"- Generating the input took {t_gen:,.0f} s (not part of the pipeline)",
        "",
        "| Stage | Seconds | Peak memory of the process so far (MB) |",
        "|---|---|---|",
    ] + [f"| {s['stage']} | {s['seconds']:,} | {s['peak_mb']:,} |" for s in stages] + [
        f"| **Total** | **{total:,.1f}** | **{max(s['peak_mb'] for s in stages):,}** |",
        "",
        f"Analysis result on top of the large tenant: {summary['findings']} findings "
        f"({', '.join(f'{k} {v}' for k, v in summary['by_level'].items())}), "
        f"pivot accounts: {', '.join(summary['pivot_accounts']) or 'none'}.",
        "",
        "Parsing streams records and keeps only a bounded buffer, so memory does not grow with the size of the",
        "input file; it grows with what the case database query results hold for the account under analysis.",
        "",
    ]
    args.out.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT / "src"))
    raise SystemExit(main())
