"""Command-line interface.

    tenanttrace run INPUT_DIR --user UPN --case CASE_DIR     all stages
    tenanttrace ingest INPUT_DIR --case CASE_DIR              hash, detect, parse, link
    tenanttrace coverage --case CASE_DIR [--user UPN]         evidence coverage and gaps
    tenanttrace analyze --case CASE_DIR --user UPN            detections, timeline, pivot
    tenanttrace report --case CASE_DIR                        HTML, PDF and JSON report
    tenanttrace version                                       tool, rule set, reference versions
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from tenanttrace import netguard


def _add_window_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--window-start", help="start of the suspected compromise window (ISO 8601, UTC if no offset)")
    p.add_argument(
        "--collected-at",
        help="when the exports were collected (ISO 8601). Used to reason about retention. "
        "Defaults to the latest event in any input.",
    )
    p.add_argument("--ipdb", help="optional offline IP location CSV the analyst already has (never downloaded)")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="tenanttrace", description="Offline Microsoft 365 BEC / account takeover investigation")
    ap.add_argument("-q", "--quiet", action="store_true", help="do not echo processing steps")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("run", help="ingest, coverage, analyze and report in one go")
    p.add_argument("input_dir", type=Path)
    p.add_argument("--user", required=True, help="UPN of the compromised account")
    p.add_argument("--case", required=True, type=Path, help="case folder to create")
    p.add_argument("--force", action="store_true", help="replace an existing TenantTrace case folder")
    p.add_argument("--no-pdf", action="store_true", help="skip the PDF")
    _add_window_args(p)

    p = sub.add_parser("ingest", help="hash, detect formats, parse and link")
    p.add_argument("input_dir", type=Path)
    p.add_argument("--case", required=True, type=Path)
    p.add_argument("--force", action="store_true")

    p = sub.add_parser("coverage", help="evidence coverage and gap analysis")
    p.add_argument("--case", required=True, type=Path)
    p.add_argument("--user", help="UPN of the compromised account (defaults to the case user)")
    _add_window_args(p)

    p = sub.add_parser("analyze", help="detections, timeline and tenant pivot")
    p.add_argument("--case", required=True, type=Path)
    p.add_argument("--user", help="UPN of the compromised account (defaults to the case user)")
    _add_window_args(p)

    p = sub.add_parser("report", help="render HTML, PDF and JSON")
    p.add_argument("--case", required=True, type=Path)
    p.add_argument("--no-pdf", action="store_true")

    sub.add_parser("version", help="print tool, rule set and reference table versions")
    return ap


def main(argv: list[str] | None = None) -> int:
    netguard.install()
    args = build_parser().parse_args(argv)
    from tenanttrace import pipeline
    from tenanttrace.case import Case

    if args.cmd == "version":
        print(json.dumps(pipeline.tool_versions(), indent=2))
        return 0

    case = Case(args.case, echo=not args.quiet)
    try:
        if args.cmd == "ingest":
            m = pipeline.ingest(args.input_dir, case, force=args.force)
            print(f"case: {case.root}")
            print(json.dumps(m["totals"], indent=2))
        elif args.cmd == "run":
            out = pipeline.run_all(
                args.input_dir,
                case,
                user=args.user,
                force=args.force,
                window_start=args.window_start,
                collected_at=args.collected_at,
                ipdb=args.ipdb,
                pdf=not args.no_pdf,
            )
            print(f"case: {case.root}")
            for k, v in out.get("report", {}).items():
                print(f"{k}: {v}")
        elif args.cmd == "coverage":
            cov = pipeline.coverage(case, user=args.user, window_start=args.window_start,
                                    collected_at=args.collected_at, ipdb=args.ipdb)
            print(json.dumps(cov.get("summary", {}), indent=2))
        elif args.cmd == "analyze":
            res = pipeline.analyze(case, user=args.user, window_start=args.window_start,
                                   collected_at=args.collected_at, ipdb=args.ipdb)
            print(json.dumps(res.get("summary", {}), indent=2))
        elif args.cmd == "report":
            out = pipeline.report(case, pdf=not args.no_pdf)
            for k, v in out.items():
                print(f"{k}: {v}")
    except (FileExistsError, FileNotFoundError, NotADirectoryError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
