"""Generated exports match the documented layouts field for field (docs/sources/layouts.yaml).

These tests read the generated files with the standard library only, never with TenantTrace's
parsers, and compare them with the layout transcription of the documentation.
"""

from __future__ import annotations

import ast
import csv
import io
import json
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
LAYOUTS = yaml.safe_load((ROOT / "docs" / "sources" / "layouts.yaml").read_text(encoding="utf-8"))
CSV_FORMATS = {"purview_ual_csv", "purview_ual_csv_v2", "ps_ual_csv", "entra_signin_csv"}


def _decode(raw: bytes) -> str:
    if raw.startswith(b"\xff\xfe"):
        return raw[2:].decode("utf-16-le")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8")
    return raw.decode("utf-8")


def _files(corpus_dir: Path):
    for gt_path in sorted(corpus_dir.glob("*/ground_truth.json")):
        gt = json.loads(gt_path.read_text(encoding="utf-8"))
        for f in gt["files"]:
            yield gt["scenario"], f["format"], gt_path.parent / "exports" / f["path"], f


def _csv_rows(path: Path):
    text = _decode(path.read_bytes())
    lines = text.split("\r\n", 1)
    if lines[0].startswith("#TYPE"):
        text = lines[1]
    return list(csv.reader(io.StringIO(text)))


def _audit_records(fmt: str, path: Path):
    if fmt in ("purview_ual_csv", "purview_ual_csv_v2", "ps_ual_csv"):
        rows = _csv_rows(path)
        idx = rows[0].index("AuditData")
        for r in rows[1:]:
            yield json.loads(r[idx])
    elif fmt == "extractor_suite_ual_json":
        for wrapper in json.loads(_decode(path.read_bytes())):
            assert sorted(wrapper) == sorted(LAYOUTS["extractor_suite_ual_json_wrapper"]["keys"])
            yield wrapper["AuditData"]
    elif fmt == "hawk_raw_json":
        for wrapper in json.loads(_decode(path.read_bytes())):
            assert sorted(wrapper) == sorted(LAYOUTS["hawk_raw_json_wrapper"]["keys"])
            assert isinstance(wrapper["AuditData"], str)      # ConvertTo-Json keeps it a string
            yield json.loads(wrapper["AuditData"])


def _signin_objects(fmt: str, path: Path):
    text = _decode(path.read_bytes())
    dec = json.JSONDecoder()
    pos = 0
    while True:
        while pos < len(text) and text[pos] in " \r\n\t":
            pos += 1
        if pos >= len(text):
            break
        arr, pos = dec.raw_decode(text, pos)
        yield from arr


def test_every_export_format_is_covered(corpus_dir):
    formats = {fmt for _, fmt, _, _ in _files(corpus_dir)}
    assert {"purview_ual_csv", "purview_ual_csv_v2", "ps_ual_csv", "entra_signin_csv", "entra_signin_json",
            "extractor_suite_ual_json", "extractor_suite_signin_json"} <= formats


def test_csv_headers_match_documented_columns(corpus_dir):
    seen = 0
    for _, fmt, path, _ in _files(corpus_dir):
        if fmt not in CSV_FORMATS:
            continue
        rows = _csv_rows(path)
        assert rows[0] == LAYOUTS["csv_layouts"][fmt]["columns"], path
        assert all(len(r) == len(rows[0]) for r in rows[1:]), path
        seen += 1
    assert seen >= 8


def test_auditdata_fields_are_documented(corpus_dir):
    common = set(LAYOUTS["auditdata_common_required"]) | set(LAYOUTS["auditdata_common_optional"])
    pattern = re.compile(LAYOUTS["creation_time_pattern"])
    aac_keys = set(LAYOUTS["app_access_context"])
    checked = 0
    for _, fmt, path, _ in _files(corpus_dir):
        for ad in _audit_records(fmt, path):
            missing = [k for k in LAYOUTS["auditdata_common_required"] if k not in ad]
            assert not missing, (path, ad["Operation"], missing)
            assert pattern.match(ad["CreationTime"]), ad["CreationTime"]
            spec = LAYOUTS["auditdata_by_record_type"][ad["RecordType"]]
            allowed = common | set(spec["documented"]) | set(spec.get("documented_variants", [])) | set(
                spec.get("unconfirmed", []))
            extra = set(ad) - allowed
            assert not extra, (path, ad["Operation"], sorted(extra))
            if "AppAccessContext" in ad:
                assert set(ad["AppAccessContext"]) <= aac_keys
            checked += 1
    assert checked > 5000


def test_signin_json_fields_are_documented(corpus_dir):
    top = set(LAYOUTS["graph_signin_beta"])
    checked = 0
    for _, fmt, path, _ in _files(corpus_dir):
        if fmt not in ("entra_signin_json", "extractor_suite_signin_json"):
            continue
        for obj in _signin_objects(fmt, path):
            assert set(obj) <= top, sorted(set(obj) - top)
            assert set(obj["deviceDetail"]) <= set(LAYOUTS["graph_device_detail"])
            assert set(obj["location"]) <= set(LAYOUTS["graph_location"])
            assert set(obj["location"]["geoCoordinates"]) <= set(LAYOUTS["graph_geo"])
            assert set(obj["status"]) <= set(LAYOUTS["graph_status"])
            assert set(obj["mfaDetail"]) <= set(LAYOUTS["graph_mfa_detail"])
            assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", obj["createdDateTime"])
            checked += 1
    assert checked > 1000


def test_hawk_flattened_columns_follow_the_documented_order(corpus_dir):
    seen = 0
    for _, fmt, path, _ in _files(corpus_dir):
        if fmt != "hawk_flat_csv":
            continue
        header = _csv_rows(path)[0]
        lead = LAYOUTS["hawk_auth_lead"] if path.name.startswith("Converted_") else LAYOUTS["hawk_simple_lead"]
        present = [c for c in lead if c in header]
        assert header[:len(present)] == present, (path.name, header[:8])
        params = [c for c in header if c.startswith("Param_")]
        assert params == sorted(params)
        assert "AuditData" not in header
        seen += 1
    assert seen >= 2


def test_record_counts_in_ground_truth_match_files(corpus_dir):
    for _, fmt, path, f in _files(corpus_dir):
        if fmt in CSV_FORMATS or fmt == "hawk_flat_csv":
            n = len(_csv_rows(path)) - 1
        elif fmt in ("extractor_suite_ual_json", "hawk_raw_json"):
            n = len(json.loads(_decode(path.read_bytes())))
        else:
            n = sum(1 for _ in _signin_objects(fmt, path))
        assert n == f["records"], path


def test_corpus_uses_only_reserved_names_and_documentation_ips(corpus_dir):
    ip4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
    allowed_prefixes = ("192.0.2.", "198.51.100.", "203.0.113.")
    for _, fmt, path, _ in _files(corpus_dir):
        text = _decode(path.read_bytes())
        for m in ip4.finditer(text):
            ip = m.group(0)
            # version strings such as 15.20.8000.010 are not addresses
            if any(int(o) > 255 for o in m.groups()) or ip.startswith(("15.20.", "16.0.", "128.0.", "126.0.")):
                continue
            assert ip.startswith(allowed_prefixes), (path, ip)
        for dom in re.findall(r"@([A-Za-z0-9.-]+)", text):
            assert dom.endswith((".example", "example.com", "example.net", "example.org")), (path, dom)


def test_generator_never_imports_tenanttrace():
    for py in (ROOT / "src" / "ttcorpus").rglob("*.py"):
        tree = ast.parse(py.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert not any(a.name.startswith("tenanttrace") for a in node.names), py
            if isinstance(node, ast.ImportFrom):
                assert not (node.module or "").startswith("tenanttrace"), py


def test_ground_truth_shape(corpus_dir):
    for gt_path in corpus_dir.glob("*/ground_truth.json"):
        gt = json.loads(gt_path.read_text(encoding="utf-8"))
        assert gt["primary_user"] in gt["users"]
        if gt["kind"] in ("attack", "degraded"):
            assert gt["expected_findings"], gt["scenario"]
        for item in gt["expected_findings"]:
            step = next(s for s in gt["steps"] if s["id"] == item["truth_id"])
            assert any(r["exported"] for r in step["records"])
