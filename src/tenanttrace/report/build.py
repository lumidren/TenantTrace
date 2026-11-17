"""Write the report: report.json (the export), report.html (self-contained) and report.pdf."""

from __future__ import annotations

import json
from importlib import resources
from typing import Any

from tenanttrace.case import Case, ProcessingLog

PLACEHOLDER = "__TT_REPORT_DATA__"


def template_html() -> str:
    return resources.files("tenanttrace.report").joinpath("template.html").read_text(encoding="utf-8")


def embed(template: str, data: dict[str, Any]) -> str:
    if PLACEHOLDER not in template:
        raise ValueError("report template has no data placeholder")
    payload = json.dumps(data, ensure_ascii=False, sort_keys=True)
    # inside <script type="application/json">, "<" must not open a tag; \u003c is the same JSON string
    payload = payload.replace("<", "\\u003c").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    return template.replace(PLACEHOLDER, payload, 1)


def build_reports(case: Case, pdf: bool, log: ProcessingLog) -> dict[str, str]:
    from tenanttrace.report.data import build_report_data

    out_dir = case.report_dir
    out_dir.mkdir(exist_ok=True)
    data = build_report_data(case)
    bad = [e for e, d in data["events"].items() if d.get("raw", {}).get("verified") is False]
    if bad:
        log.write("report", f"{len(bad)} evidence record(s) no longer match their ingest hash", events=bad[:20])
    outputs: dict[str, str] = {}
    jpath = out_dir / "report.json"
    jpath.write_text(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    outputs["json"] = str(jpath)
    hpath = out_dir / "report.html"
    hpath.write_text(embed(template_html(), data), encoding="utf-8")
    outputs["html"] = str(hpath)
    if pdf:
        from tenanttrace.report.pdf import render_pdf

        outputs["pdf"] = str(render_pdf(data, out_dir / "report.pdf"))
    log.write("report", f"report written: {', '.join(outputs)}", events_embedded=len(data["events"]),
              findings=len(data["findings"]))
    return outputs
