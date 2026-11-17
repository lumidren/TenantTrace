"""Tenant pivot: other accounts in the supplied logs that share the attacker's indicators.

Indicators are taken from the primary account's findings at probable or confirmed level
(falling back to possible-level findings, labelled as weaker, when there are none). An
indicator that the account itself used during its baseline is never used for the pivot,
because shared office IP addresses and common clients would otherwise list the whole tenant.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from tenanttrace.rules.baseline import Baseline, ua_family
from tenanttrace.store import CaseStore

KIND_STRENGTH = {"session_id": "strong", "token_id": "strong", "ip": "medium", "app_id": "medium",
                 "user_agent": "weak"}
STRENGTH_RANK = {"strong": 3, "medium": 2, "weak": 1}
MAX_EXAMPLES = 10


def collect_indicators(findings: list[dict[str, Any]], baseline: Baseline) -> tuple[dict[str, dict[str, list[str]]], str]:
    strong = [f for f in findings if f["level"] in ("confirmed", "probable")]
    basis = "findings at probable or confirmed level"
    if not strong:
        strong = findings
        basis = "possible-level findings only (no finding reached probable); treat matches as weak leads"
    out: dict[str, dict[str, list[str]]] = {k: {} for k in KIND_STRENGTH}
    keymap = {"ips": "ip", "session_ids": "session_id", "token_ids": "token_id", "user_agents": "user_agent",
              "app_ids": "app_id"}
    for f in strong:
        for k, kind in keymap.items():
            if kind == "app_id" and not f.get("pivot_app"):
                continue   # only consent / app-access findings make an application ID an attacker indicator
            for v in f["indicators"].get(k, []):
                if kind == "ip" and v in baseline.ips:
                    continue
                if kind == "app_id" and v.lower() in baseline.app_ids:
                    continue
                if kind == "user_agent" and ua_family(v) in baseline.ua_families:
                    continue   # the account's own kind of browser or client is not an attacker indicator
                out[kind].setdefault(v, []).append(f["id"])
    # app ids carried in consent details
    for f in strong:
        for app in f.get("extra", {}).get("app_ids", []) or []:
            out["app_id"].setdefault(app.lower(), []).append(f["id"])
    return out, basis


COMMON_SHARE = 0.5


def tenant_pivot(store: CaseStore, user: str, findings: list[dict[str, Any]], baseline: Baseline) -> list[dict[str, Any]]:
    indicators, basis = collect_indicators(findings, baseline)
    # an indicator that most accounts in the tenant already shared before the compromise window
    # (a corporate proxy, a standard browser build) does not single anything out; an attacker address
    # that touched many accounts during the attack is exactly what the pivot is for
    n_accounts = store.conn.execute("SELECT COUNT(DISTINCT actor) FROM events WHERE actor LIKE '%@%'").fetchone()[0]
    dropped: list[str] = []
    for kind in ("ip", "user_agent", "app_id"):
        for value in list(indicators[kind]):
            col = "lower(app_id)" if kind == "app_id" else kind
            v = value.lower() if kind == "app_id" else value
            n = store.conn.execute(
                f"SELECT COUNT(DISTINCT actor) FROM events WHERE {col} = ? AND actor LIKE '%@%' AND ts_utc < ?",
                (v, baseline.end or "9999")).fetchone()[0]
            if n_accounts >= 4 and n > COMMON_SHARE * n_accounts:
                dropped.append(f"{kind} {value[:60]} (used by {n} of {n_accounts} accounts before the window)")
                del indicators[kind][value]
    # user agents of the account's own baseline are not attacker indicators
    hits: dict[str, dict[str, Any]] = {}
    for kind, values in indicators.items():
        if not values:
            continue
        col = kind
        for value in sorted(values):
            if kind == "app_id":
                where, params = "lower(app_id) = ? AND actor != ?", (value.lower(), user)
            else:
                where, params = f"{col} = ? AND actor != ? AND actor != ''", (value, user)
            rows = store.conn.execute(
                f"SELECT actor, event_id, ts_utc, action, outcome FROM events WHERE {where} "
                f"AND (link_role IS NULL OR link_role NOT IN ('duplicate','corroborating')) ORDER BY ts_utc, event_id",
                params).fetchall()
            for actor, eid, ts, action, outcome in rows:
                h = hits.setdefault(actor, {"account": actor, "matches": defaultdict(lambda: {
                    "count": 0, "first": "", "last": "", "examples": [], "actions": set(), "from_findings": set()})})
                m = h["matches"][(kind, value)]
                m["count"] += 1
                m["first"] = m["first"] or ts
                m["last"] = ts
                m["actions"].add(f"{action}:{outcome}")
                m["from_findings"].update(values[value])
                if len(m["examples"]) < MAX_EXAMPLES:
                    m["examples"].append(eid)
    out = []
    for actor, h in hits.items():
        matches = []
        best = 0
        for (kind, value), m in sorted(h["matches"].items()):
            strength = KIND_STRENGTH[kind]
            best = max(best, STRENGTH_RANK[strength])
            matches.append({"kind": kind, "value": value, "strength": strength, "count": m["count"],
                            "first": m["first"], "last": m["last"], "example_event_ids": m["examples"],
                            "actions": sorted(m["actions"]), "from_findings": sorted(m["from_findings"])})
        out.append({"account": actor, "strength": {3: "strong", 2: "medium", 1: "weak"}[best],
                    "indicator_count": len(matches), "matches": matches, "basis": basis, "not_used": dropped,
                    "first": min(m["first"] for m in matches), "last": max(m["last"] for m in matches)})
    out.sort(key=lambda x: (-STRENGTH_RANK[x["strength"]], -x["indicator_count"], x["account"]))
    return out
