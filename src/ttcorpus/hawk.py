"""Hawk (T0pCyber, v4.0) output layout for one investigated user (docs/sources/collectors.md section 2).

Written from the collector notes, independently of TenantTrace's parsers:

    Hawk_<TenantName>_<yyyyMMdd_HHmmss>/
      <upn>/Converted_Authentication_Logs_<short>.csv     UAL sign-in records, AuditData flattened
      <upn>/MailItemsAccessed_<upn>.json                   raw Search-UnifiedAuditLog objects
      <upn>/Simple_MailItemsAccessed_<upn>.csv             the same records flattened
      <upn>/ExchangeItem_Logs_<short>.json                 raw mailbox-audit records (ExchangeItem)
      <upn>/User_Changes_<short>.json                      raw admin changes made to the user

Raw files are ConvertTo-Json of the cmdlet's objects, so AuditData stays a JSON string and
CreationDate is a Windows PowerShell /Date(ms)/ value. CSVs are Export-Csv -NoTypeInformation
-Encoding UTF8 (UTF-8 with BOM). Flattened ("Simple_") column order: the fixed leading columns,
then Param_* columns sorted, then the rest. The exact column sets vary by run (unverified).
"""

from __future__ import annotations

import json
from datetime import timezone
from pathlib import Path
from typing import Any

from ttcorpus.engine import RT, World
from ttcorpus.model import AuditOp
from ttcorpus.output import write_csv
from ttcorpus.writers import audit_data

RT_NAME = {v: k for k, v in RT.items()}
SIMPLE_LEAD = ["CreationTime", "Workload", "RecordType", "Operation", "ResultStatus", "ClientIP", "UserId", "Id",
               "OrganizationId", "UserType", "UserKey", "ObjectId", "Scope", "AppAccessContext"]
AUTH_LEAD = ["CreationTime", "UserId", "Workload", "ClientIP", "CountryName", "KnownMicrosoftIP"]


def _ps_date(op: AuditOp) -> str:
    return f"/Date({int(op.t.astimezone(timezone.utc).timestamp() * 1000)})/"


def _wrapper(op: AuditOp, w: World, i: int, total: int) -> dict[str, Any]:
    return {"RunspaceId": "5b1f0c7e-6d2a-4c38-9a40-2f6e8d1c3b55", "RecordType": RT_NAME.get(op.record_type),
            "CreationDate": _ps_date(op), "UserIds": op.user.upn, "Operations": op.operation,
            "AuditData": json.dumps(audit_data(op, w), separators=(",", ":")), "ResultIndex": i,
            "ResultCount": total, "Identity": op.record_id, "IsValid": True, "ObjectState": "Unchanged"}


def _write_json(path: Path, ops: list[AuditOp], w: World) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    items = [_wrapper(o, w, i, len(ops)) for i, o in enumerate(ops, 1)]
    text = json.dumps(items, indent=4, ensure_ascii=False).replace("\n", "\r\n") + "\r\n"
    path.write_bytes(b"\xef\xbb\xbf" + text.encode("utf-8"))
    return len(items)


def _hashtable(d: dict[str, Any]) -> str:
    """How PowerShell renders a nested object when Export-Csv flattens it: @{Key=Value; ...}."""
    return "@{" + "; ".join(f"{k}={v}" for k, v in d.items()) + "}"


def _flatten(ad: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in ad.items():
        if k == "Parameters":
            for p in v:
                out[f"Param_{p['Name']}"] = str(p.get("Value", ""))
            out["ParameterString"] = " ".join(f"-{p['Name']} {p.get('Value', '')}" for p in v)
        elif k == "AppAccessContext":
            out[k] = _hashtable(v)
        elif k == "ExtendedProperties":
            for p in v:
                out[p["Name"]] = str(p.get("Value", ""))
        elif k in ("Actor", "Target"):
            out[k] = ";".join(f"{x.get('ID')}:{x.get('Type')}" for x in v)
        elif isinstance(v, (dict, list)):
            out[k] = "System.Object[]" if isinstance(v, list) else _hashtable(v)
        else:
            out[k] = "" if v is None else str(v)
    return out


def _write_flat(path: Path, ops: list[AuditOp], w: World, lead: list[str], extra: dict[str, str] | None = None) -> int:
    rows = []
    for o in ops:
        f = _flatten(audit_data(o, w))
        if extra:
            f.update(extra)
        rows.append(f)
    cols = [c for c in lead if any(c in r for r in rows) or c in (extra or {})]
    params = sorted({k for r in rows for k in r if k.startswith("Param_")})
    rest = sorted({k for r in rows for k in r} - set(cols) - set(params))
    header = cols + (["ParameterString"] if "ParameterString" in rest else []) + params + [c for c in rest if c != "ParameterString"]
    return write_csv(path, header, [[r.get(c, "") for c in header] for r in rows], encoding="utf-8-sig")


def write_hawk(w: World, spec: dict[str, Any], root: Path, ops: list[AuditOp]) -> list[dict[str, Any]]:
    from ttcorpus.model import utc

    user = w.user(spec["primary_user"])
    short = user.upn.split("@")[0]
    stamp = utc(spec["collected_at"]).strftime("%Y%m%d_%H%M%S")
    tenant = spec["tenant"]["name"].replace(" ", "_")
    base = root / f"Hawk_{tenant}_{stamp}" / user.upn
    mine = [o for o in ops if o.user.upn == user.upn or o.payload.get("MailboxOwnerUPN") == user.upn]
    files = []

    def add(path: Path, fmt: str, n: int, sel: list[AuditOp]) -> None:
        files.append({"path": path.relative_to(root.parent).as_posix(), "format": fmt, "records": n,
                      "degrade": {}, "record_ids": [o.record_id for o in sel]})

    auth = [o for o in mine if o.record_type in (RT["AzureActiveDirectoryStsLogon"],)]
    p = base / f"Converted_Authentication_Logs_{short}.csv"
    add(p, "hawk_flat_csv", _write_flat(p, auth, w, AUTH_LEAD, {"CountryName": "", "KnownMicrosoftIP": "False"}), auth)
    mia = [o for o in mine if o.operation == "MailItemsAccessed"]
    p = base / f"MailItemsAccessed_{user.upn}.json"
    add(p, "hawk_raw_json", _write_json(p, mia, w), mia)
    p = base / f"Simple_MailItemsAccessed_{user.upn}.csv"
    add(p, "hawk_flat_csv", _write_flat(p, mia, w, SIMPLE_LEAD), mia)
    items = [o for o in mine if o.record_type == RT["ExchangeItem"]]
    p = base / f"ExchangeItem_Logs_{short}.json"
    add(p, "hawk_raw_json", _write_json(p, items, w), items)
    changes = [o for o in ops if o.record_type == RT["ExchangeAdmin"]
               and (o.user.upn == user.upn or any(user.upn in str(x.get("Value", "")) for x in o.payload.get("Parameters", [])))]
    p = base / f"User_Changes_{short}.json"
    add(p, "hawk_raw_json", _write_json(p, changes, w), changes)
    return files
