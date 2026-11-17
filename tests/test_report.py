"""Report outputs: every finding links to embedded, re-verified evidence; HTML, PDF and JSON carry
the same findings; the HTML is self-contained."""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import pytest

from tenanttrace.case import Case
from tenanttrace.pipeline import report, run_all
from tenanttrace.report.build import PLACEHOLDER, template_html

USER = "dana.whitfield@harborlane.example"


@pytest.fixture(scope="module")
def demo(corpus_dir, tmp_path_factory):
    case = Case(tmp_path_factory.mktemp("rep") / "case")
    out = run_all(corpus_dir / "demo_bec" / "exports", case, user=USER, collected_at="2026-11-06T17:00:00Z", pdf=True)
    return case, out["report"]


def _embedded(html: str) -> dict:
    m = re.search(r'<script id="tt-data" type="application/json">(.*?)</script>', html, re.S)
    assert m, "no embedded data"
    return json.loads(m.group(1))


def test_all_three_outputs_exist(demo):
    case, out = demo
    for k in ("html", "pdf", "json"):
        assert Path(out[k]).exists() and Path(out[k]).stat().st_size > 1000


def test_every_finding_links_to_embedded_verified_evidence(demo):
    case, out = demo
    data = json.loads(Path(out["json"]).read_text(encoding="utf-8"))
    assert data["findings"]
    for f in data["findings"]:
        assert f["event_ids"]
        for eid in f["event_ids"]:
            ev = data["events"][eid]                     # embedded
            assert ev["raw"]["available"] and ev["raw"]["verified"] is True, eid
            assert ev["file"] and ev["line_start"] > 0 and len(ev["raw_sha256"]) == 64
    for st in data["timeline"]["steps"]:
        for eid in st["event_ids"]:
            assert eid in data["events"]
    for p in data["pivot"]:
        for m in p["matches"]:
            assert all(e in data["events"] for e in m["example_event_ids"])


def test_html_pdf_and_json_carry_the_same_findings(demo):
    from pypdf import PdfReader

    case, out = demo
    data = json.loads(Path(out["json"]).read_text(encoding="utf-8"))
    html_data = _embedded(Path(out["html"]).read_text(encoding="utf-8"))
    ids = sorted(f["id"] for f in data["findings"])
    assert sorted(f["id"] for f in html_data["findings"]) == ids
    pdf_text = "".join(p.extract_text() for p in PdfReader(out["pdf"]).pages)
    for i in ids:
        assert i in pdf_text, i
    # and the same levels
    assert {f["id"]: f["level"] for f in html_data["findings"]} == {f["id"]: f["level"] for f in data["findings"]}


def test_html_is_self_contained_and_offline(demo):
    case, out = demo
    html = Path(out["html"]).read_text(encoding="utf-8")
    assert PLACEHOLDER not in html
    assert "Content-Security-Policy" in html and "connect-src 'none'" in html
    assert not re.search(r"<script[^>]+\bsrc=", html, re.I)
    assert not re.search(r"<link[^>]+\bhref=", html, re.I)
    assert not re.search(r"@import|url\(\s*['\"]?https?:", html, re.I)
    # only clickable citation links point outside, and only to Microsoft documentation
    for url in re.findall(r'href="(https?://[^"]+)"', html):
        assert url.startswith("https://learn.microsoft.com/"), url


def test_template_is_the_built_ui():
    t = template_html()
    assert PLACEHOLDER in t and "<script type=\"module\">" in t and "<style>" in t
    assert "./assets/" not in t


def test_embedded_json_cannot_break_out_of_its_script_tag(tmp_path):
    from tenanttrace.report.build import embed

    html = embed(template_html(), {"evil": "</script><script>alert(1)</script>", "case": {}})
    data = _embedded(html)
    assert data["evil"] == "</script><script>alert(1)</script>"


def test_changed_input_is_flagged_at_report_time(corpus_dir, tmp_path):
    """Simulate an input altered after ingest (on a copy): the report must say the hash no longer matches."""
    src = tmp_path / "in"
    shutil.copytree(corpus_dir / "demo_bec" / "exports", src)
    case = Case(tmp_path / "case")
    run_all(src, case, user=USER, collected_at="2026-11-06T17:00:00Z", pdf=False)
    data = json.loads((case.report_dir / "report.json").read_text(encoding="utf-8"))
    rule = next(f for f in data["findings"] if f["rule_id"] == "TT-MAIL-001")
    ev = data["events"][rule["event_ids"][0]]
    path = src / ev["file"]
    raw = path.read_bytes()
    lines = raw.split(b"\n")
    lines[ev["line_start"] - 1] = lines[ev["line_start"] - 1].replace(b"RSS Subscriptions", b"RSS Subscriptionz")
    path.write_bytes(b"\n".join(lines))
    report(case, pdf=False)
    data = json.loads((case.report_dir / "report.json").read_text(encoding="utf-8"))
    assert data["events"][rule["event_ids"][0]]["raw"]["verified"] is False
    assert "no longer match" in (case.root / "processing.log").read_text(encoding="utf-8")
