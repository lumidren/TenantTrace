"""Generate a scenario's exports and its ground-truth file."""

from __future__ import annotations

import copy
import json
from datetime import datetime, timedelta, timezone
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from ttcorpus import GENERATOR_VERSION
from ttcorpus.engine import World, simulate
from ttcorpus.model import AuditOp, SignIn, utc
from ttcorpus.output import write_json_array
from ttcorpus.writers import (
    audit_data,
    ps_creation_date,
    signin_json,
    write_entra_csv,
    write_entra_json,
    write_ps_csv,
    write_purview_csv,
)


def _scenario_dir():
    return resources.files("ttcorpus").joinpath("scenarios")


def list_scenarios() -> list[str]:
    out = []
    d = _scenario_dir()
    for p in sorted(x.name for x in d.iterdir()):
        if p.endswith(".yaml") and p != "degraded.yaml":
            out.append(p[:-5])
    for v in _variants():
        out.append(v["id"])
    return out


def _variants() -> list[dict[str, Any]]:
    data = yaml.safe_load(_scenario_dir().joinpath("degraded.yaml").read_text(encoding="utf-8"))
    return data.get("variants", [])


def load_scenario(sid: str) -> dict[str, Any]:
    d = _scenario_dir()
    f = d.joinpath(f"{sid}.yaml")
    if f.is_file():
        return yaml.safe_load(f.read_text(encoding="utf-8"))
    for v in _variants():
        if v["id"] == sid:
            base = copy.deepcopy(load_scenario(v["base"]))
            base["id"] = v["id"]
            base["title"] = v.get("title", base["title"])
            base["kind"] = "degraded"
            base["base"] = v["base"]
            base["degrade"] = v.get("degrade", {})
            truth = base.setdefault("truth", {})
            for k, val in (v.get("truth") or {}).items():
                truth[k] = val
            return base
    raise KeyError(f"unknown scenario {sid!r}")


# ----------------------------------------------------------------------------- exports


def _apply_degrade(spec: dict[str, Any], fmt: str, signins: list[SignIn], ops: list[AuditOp],
                   collected: datetime) -> tuple[list[SignIn], list[AuditOp], dict[str, Any]]:
    dg = spec.get("degrade") or {}
    note: dict[str, Any] = {}
    ret = (dg.get("retention_days") or {}).get(fmt)
    if ret:
        cutoff = collected - timedelta(days=float(ret))
        signins = [s for s in signins if s.t >= cutoff]
        ops = [o for o in ops if o.t >= cutoff]
        note["retention_days"] = ret
    win = dg.get("drop_window")
    if win and fmt in win.get("formats", []):
        a, b = utc(win["from"]), utc(win["to"])
        ops = [o for o in ops if not (a <= o.t < b)]
        signins = [s for s in signins if not (a <= s.t < b)]
        note["dropped_window"] = [win["from"], win["to"]]
    drop_ops = set(dg.get("drop_operations") or [])
    if drop_ops:
        ops = [o for o in ops if o.operation not in drop_ops]
        note["dropped_operations"] = sorted(drop_ops)
    if dg.get("truncate_format") == fmt:
        until = utc(dg["keep_until"])
        note["truncated_after"] = dg["keep_until"]
        note["original_records"] = len(ops)
        ops = [o for o in ops if o.t <= until]
        signins = [s for s in signins if s.t <= until]
    return signins, ops, note


def write_exports(w: World, spec: dict[str, Any], out: Path) -> list[dict[str, Any]]:
    collected = utc(spec["collected_at"])
    removed = set((spec.get("degrade") or {}).get("remove_formats") or [])
    files = []
    for ex in spec["exports"]:
        fmt = ex["format"]
        if fmt in removed:
            continue
        path = out / ex["path"]
        which = ex.get("which")
        signins = [s for s in w.signins if which is None or (which == "interactive") == s.interactive]
        ops = list(w.ops)
        signins, ops, note = _apply_degrade(spec, fmt, signins, ops, collected)
        record_ids: list[str] = []
        if fmt == "purview_ual_csv":
            n = write_purview_csv(w, ops, path)
            record_ids = [o.record_id for o in ops]
        elif fmt == "purview_ual_csv_v2":
            n = write_purview_csv(w, ops, path, v2=True)
            record_ids = [o.record_id for o in ops]
        elif fmt == "ps_ual_csv":
            total = note.get("original_records")
            n = write_ps_csv(w, ops, path, encoding=ex.get("encoding", "utf-16-le"), result_count=total,
                             type_line=bool(ex.get("type_line")))
            record_ids = [o.record_id for o in ops]
        elif fmt == "entra_signin_csv":
            n = write_entra_csv(w, signins, path)
            record_ids = [s.request_id for s in signins]
        elif fmt == "entra_signin_json":
            n = write_entra_json(w, signins, path)
            record_ids = [s.request_id for s in signins]
        elif fmt == "extractor_suite":
            sub = write_extractor_suite(w, spec, path, ops, signins)
            files.extend(sub)
            continue
        else:
            raise ValueError(f"unknown export format {fmt}")
        files.append({"path": path.relative_to(out).as_posix(), "format": fmt, "records": n,
                      "which": which, "degrade": note, "record_ids": record_ids})
    return files


def _ps_date(t: datetime) -> str:
    """Windows PowerShell 5.1 ConvertTo-Json writes DateTime as \\/Date(ms)\\/ (INFERRED, see collectors.md)."""
    ms = int(t.astimezone(timezone.utc).timestamp() * 1000)
    return f"/Date({ms})/"


def write_extractor_suite(w: World, spec: dict[str, Any], root: Path, ops: list[AuditOp],
                          signins_all: list[SignIn]) -> list[dict[str, Any]]:
    """Microsoft-Extractor-Suite v4.1.0 layout (collectors.md 1.1-1.4): Get-UAL -Output JSON and
    Get-GraphEntraSignInLogs (combined interactive and non-interactive folder, per-page files)."""
    collected = utc(spec["collected_at"])
    stamp = collected.strftime("%Y%m%d-%H%M%S")
    files = []
    # Get-UAL JSON: wrapper objects with AuditData parsed; one file per time window.
    start = utc(spec["period"]["start"])
    mid = start + (collected - start) / 2
    windows = [(start, mid), (mid, collected)]
    runspace = "2f1d6a64-0c0e-4b7c-9a52-6f0e1c3d5b77"
    for ws, we in windows:
        part = [o for o in ops if ws <= o.t < we]
        name = f"UAL-{ws.strftime('%Y%m%d%H%M%S')}-{we.strftime('%Y%m%d%H%M%S')}.json"
        path = root / "UnifiedAuditLog" / stamp / name
        items = []
        for i, o in enumerate(sorted(part, key=lambda x: x.t, reverse=True), 1):
            items.append({
                "RunspaceId": runspace,
                "RecordType": o.record_type,
                "CreationDate": _ps_date(o.t),
                "UserIds": o.user.upn,
                "Operations": o.operation,
                "AuditData": audit_data(o, w),
                "ResultIndex": i,
                "ResultCount": len(part),
                "Identity": o.record_id,
                "IsValid": True,
                "ObjectState": "New",
            })
        path.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(items, indent=4, ensure_ascii=False).replace("\n", "\r\n") + "\r\n"
        path.write_bytes(b"\xef\xbb\xbf" + text.encode("utf-8"))
        files.append({"path": path.relative_to(root.parent).as_posix(), "format": "extractor_suite_ual_json",
                      "records": len(items), "degrade": {}, "record_ids": [o.record_id for o in part]})
    # Get-GraphEntraSignInLogs: Graph beta pages appended to one file per second.
    folder = root / "EntraID" / f"{stamp}-SignInLogs" / "interactiveUser & nonInteractiveUser"
    fname = f"{collected.strftime('%Y%m%d%H%M%S')}-interactiveUser-nonInteractiveUser-SignInLogs.json"
    path = folder / fname
    path.parent.mkdir(parents=True, exist_ok=True)
    ordered = sorted(signins_all, key=lambda s: s.t, reverse=True)
    half = len(ordered) // 2
    pages = [ordered[:half], ordered[half:]]
    chunks = []
    for page in pages:
        chunks.append(json.dumps([signin_json(w, s) for s in page], indent=4, ensure_ascii=False).replace("\n", "\r\n"))
    path.write_bytes(b"\xef\xbb\xbf" + ("\r\n".join(chunks) + "\r\n").encode("utf-8"))
    files.append({"path": path.relative_to(root.parent).as_posix(), "format": "extractor_suite_signin_json",
                  "records": len(ordered), "degrade": {}, "record_ids": [s.request_id for s in ordered]})
    return files


# ----------------------------------------------------------------------------- ground truth


def ground_truth(w: World, spec: dict[str, Any], files: list[dict[str, Any]]) -> dict[str, Any]:
    exported = set()
    for f in files:
        exported.update(f["record_ids"])
    steps: dict[str, dict[str, Any]] = {}
    for s in w.signins:
        tid = s.tags.get("truth_id")
        if tid:
            st = steps.setdefault(tid, {"id": tid, "actor_kind": s.tags.get("actor_kind"), "user": s.user.upn,
                                        "first": s.t, "records": [], "expect": s.tags.get("expect", [])})
            st["records"].append({"kind": "signin", "id": s.request_id, "exported": s.request_id in exported})
            st["first"] = min(st["first"], s.t)
    for o in w.ops:
        tid = o.tags.get("truth_id")
        if tid:
            st = steps.setdefault(tid, {"id": tid, "actor_kind": o.tags.get("actor_kind"), "user": o.user.upn,
                                        "first": o.t, "records": [], "expect": o.tags.get("expect", [])})
            st["records"].append({"kind": "ual", "operation": o.operation, "id": o.record_id,
                                  "exported": o.record_id in exported})
            st["first"] = min(st["first"], o.t)
    truth = spec.get("truth") or {}
    primary = w.user(spec["primary_user"]).upn
    drop_rules = set(truth.get("drop_expected_rules") or [])
    drop_ids = set(truth.get("drop_expected_truth_ids") or [])
    expected, unobservable = [], []
    for st in sorted(steps.values(), key=lambda x: x["first"]):
        for rule in st["expect"]:
            item = {"rule": rule, "truth_id": st["id"], "user": st["user"]}
            visible = any(r["exported"] for r in st["records"])
            if rule in drop_rules or st["id"] in drop_ids or not visible:
                item["reason"] = ("records not in the supplied exports" if not visible else "dropped by the variant")
                unobservable.append(item)
            else:
                expected.append(item)
    pivot = [w.user(k).upn for k in truth.get("pivot_users", [])]
    return {
        "scenario": spec["id"],
        "title": spec["title"],
        "kind": spec.get("kind", "attack"),
        "base": spec.get("base"),
        "generator_version": GENERATOR_VERSION,
        "tenant": {"name": spec["tenant"]["name"], "domain": w.domain, "tenant_id": w.tenant_id},
        "primary_user": primary,
        "users": [u.upn for u in w.users.values()],
        "period": spec["period"],
        "collected_at": spec["collected_at"],
        "compromise_start": truth.get("compromise_start"),
        "window_start": truth.get("window_start"),
        "steps": [{**{k: v for k, v in st.items() if k != "first"}, "first": st["first"].strftime("%Y-%m-%dT%H:%M:%SZ")}
                  for st in sorted(steps.values(), key=lambda x: x["first"])],
        "expected_findings": expected,
        "unobservable_expected": unobservable,
        "allowed_findings": truth.get("allowed_findings", []),
        "expected_gaps": truth.get("expected_gaps", []),
        "expected_not_assessable": truth.get("expected_not_assessable", []),
        "expected_pivot": pivot,
        "files": [{k: v for k, v in f.items() if k != "record_ids"} for f in files],
        "degrade": spec.get("degrade") or {},
    }


def _long(p: Path) -> Path:
    """Extended-length paths on Windows: collector layouts nest folders deeply."""
    import os

    if os.name != "nt":
        return p
    prefix = "\\\\?\\"
    s = str(p.resolve())
    return Path(s if s.startswith(prefix) else prefix + s)


def generate(sid: str, out_root: Path) -> dict[str, Any]:
    spec = load_scenario(sid)
    w = simulate(spec)
    case_dir = _long(Path(out_root)) / sid
    exports = case_dir / "exports"
    if exports.exists():
        for p in sorted(exports.rglob("*"), reverse=True):
            p.unlink() if p.is_file() else p.rmdir()
    exports.mkdir(parents=True, exist_ok=True)
    files = write_exports(w, spec, exports)
    gt = ground_truth(w, spec, files)
    (case_dir / "ground_truth.json").write_text(json.dumps(gt, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return gt


_ = (ps_creation_date, write_json_array)
