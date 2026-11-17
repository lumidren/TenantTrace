"""Normalize Microsoft Entra audit log records (Graph directoryAudit, formats section 2c)."""

from __future__ import annotations

import re
from typing import Any

from tenanttrace.ingest.timeparse import TimeParseError, parse_ts
from tenanttrace.ingest.ual import OPERATIONS, op_key
from tenanttrace.schema import Event

_GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_SCOPE = re.compile(r"Scope:\s*([^,\]\[]*)")


def normalize_directory_audit(rec: dict[str, Any]) -> Event:
    if not isinstance(rec, dict):
        raise ValueError("audit record is not a JSON object")
    when = rec.get("activityDateTime")
    if not when:
        raise ValueError("audit record has no activityDateTime")
    ev = Event()
    try:
        ev.ts_utc, ev.ts_note = parse_ts(str(when), naive_zone="utc")
    except TimeParseError as exc:
        raise ValueError(f"bad activityDateTime: {exc}") from exc
    ev.ts_original = str(when)
    ev.source = "entra_audit"
    ev.record_id = str(rec.get("id") or "")
    ev.operation = str(rec.get("activityDisplayName") or "")
    ev.category, ev.action = OPERATIONS.get(op_key(ev.operation), ("other", "other"))
    ev.correlation_id = str(rec.get("correlationId") or "")
    result = str(rec.get("result") or "").lower()
    ev.outcome = {"success": "success", "failure": "failure", "timeout": "failure"}.get(result, "unknown")
    init = rec.get("initiatedBy") or {}
    user = init.get("user") if isinstance(init, dict) else None
    app = init.get("app") if isinstance(init, dict) else None
    if isinstance(user, dict):
        ev.actor = str(user.get("userPrincipalName") or "").lower()
        ev.actor_id = str(user.get("id") or "")
        ev.ip = str(user.get("ipAddress") or "")   # the OAuth client's IP, often not the end user's (2c)
    elif isinstance(app, dict):
        ev.actor = str(app.get("servicePrincipalName") or app.get("displayName") or "").lower()
        ev.app_id = str(app.get("appId") or "")
    mods: dict[str, Any] = {}
    target_upn = ""
    target_name = ""
    for t in rec.get("targetResources") or []:
        if not isinstance(t, dict):
            continue
        if t.get("userPrincipalName") and not target_upn:
            target_upn = str(t["userPrincipalName"]).lower()
        if t.get("displayName") and not target_name:
            target_name = str(t["displayName"])
        for m in t.get("modifiedProperties") or []:
            if isinstance(m, dict) and m.get("displayName"):
                mods[str(m["displayName"])] = m.get("newValue")
    det: dict[str, Any] = {"category": rec.get("category", ""), "logged_by": rec.get("loggedByService", "")}
    if ev.category == "app_consent":
        perms = str(mods.get("ConsentAction.Permissions") or "")
        scopes: list[str] = []
        for m in _SCOPE.finditer(perms):
            scopes.extend(s for s in m.group(1).split() if s)
        det["scopes"] = sorted(set(scopes))
        if "ConsentContext.IsAdminConsent" in mods:
            det["is_admin_consent"] = "true" in str(mods["ConsentContext.IsAdminConsent"]).lower()
        ids = _GUID.findall(str(mods.get("TargetId.ServicePrincipalNames") or ""))
        if ids:
            ev.app_id = ids[0].lower()
            det["app_id"] = ev.app_id
        det["app_name"] = target_name
        ev.target = target_name
    else:
        ev.target = target_upn or target_name
        if ev.category == "auth_method":
            det["method"] = ", ".join(str(a.get("value")) for a in rec.get("additionalDetails") or []
                                      if isinstance(a, dict) and a.get("value"))[:200]
        if ev.category == "device":
            det["device_name"] = target_name
            ev.device_name = target_name
    if ev.category == "other":
        det["unmapped_operation"] = True
    ev.details = det
    return ev
