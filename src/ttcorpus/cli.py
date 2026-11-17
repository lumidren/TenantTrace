"""ttcorpus command line: generate synthetic Microsoft 365 exports with ground truth.

    ttcorpus list
    ttcorpus generate --out DIR [SCENARIO ...]       (all scenarios when none are named)
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ttcorpus.generate import generate, list_scenarios


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="ttcorpus")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    g = sub.add_parser("generate")
    g.add_argument("--out", required=True, type=Path)
    g.add_argument("scenarios", nargs="*")
    args = ap.parse_args(argv)
    if args.cmd == "list":
        for s in list_scenarios():
            print(s)
        return 0
    names = args.scenarios or list_scenarios()
    for sid in names:
        gt = generate(sid, args.out)
        print(json.dumps({"scenario": sid, "files": [(f["path"], f["records"]) for f in gt["files"]],
                          "expected_findings": len(gt["expected_findings"])}))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
