"""Report building (phase 1 placeholder: JSON export only)."""

from __future__ import annotations

from typing import Any

from tenanttrace.case import Case, ProcessingLog


def build_reports(case: Case, pdf: bool, log: ProcessingLog) -> dict[str, str]:
    case.report_dir.mkdir(exist_ok=True)
    data: dict[str, Any] = {
        "manifest": case.read_json("manifest.json"),
        "case": case.params(),
        "coverage": case.read_json("coverage.json"),
        "analysis": case.read_json("analysis.json"),
    }
    import json

    out = case.report_dir / "report.json"
    out.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    return {"json": str(out)}
