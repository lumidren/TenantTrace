"""Assemble the report data: one JSON document that the HTML, the PDF and the JSON export share.

Only the events that findings, timeline steps and pivot matches reference are embedded, each
with its raw record re-read from the original input and re-hashed now, so a reader can check that
the evidence still matches what was analysed. The full event store stays in the case database.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

from tenanttrace import TOOL_NAME, __version__
from tenanttrace.case import Case, utc_now_iso
from tenanttrace.hashing import long_path, sha256_text
from tenanttrace.ingest.readers import detect_encoding, read_head, read_spans
from tenanttrace.store import CaseStore

REPORT_FORMAT = "1"
RAW_MAX_CHARS = 20000
LEVEL_RANK = {"confirmed": 3, "probable": 2, "possible": 1}
EVENT_FIELDS = ("event_id", "ts_utc", "ts_original", "ts_note", "source", "parser", "actor", "target", "category",
                "action", "operation", "outcome", "status_code", "ip", "geo_country", "geo_region", "geo_city",
                "geo_lat", "geo_lon", "user_agent", "client_app", "app_id", "app_name", "resource", "device_id",
                "device_os", "device_browser", "interactive", "auth_requirement", "mfa_detail", "session_id",
                "token_id", "correlation_id", "request_id", "record_id", "link_role", "link_basis", "details",
                "file_id", "line_start", "col_start", "line_end", "col_end", "byte_offset", "raw_sha256")


def _referenced(analysis: dict[str, Any]) -> list[str]:
    ids: list[str] = []
    for f in analysis.get("findings", []):
        ids.extend(f["event_ids"])
    for s in analysis.get("timeline", {}).get("steps", []):
        ids.extend(s.get("event_ids", []))
        link = s.get("session_link") or {}
        if link.get("signin_event_id"):
            ids.append(link["signin_event_id"])
    for p in analysis.get("pivot", []):
        for m in p["matches"]:
            ids.extend(m["example_event_ids"])
    seen: set[str] = set()
    out = []
    for i in ids:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


def load_events(case: Case, manifest: dict[str, Any], ids: list[str]) -> dict[str, dict[str, Any]]:
    events: dict[str, dict[str, Any]] = {}
    with CaseStore(case.db_path) as store:
        files = {f["file_id"]: f for f in store.files()}
        for eid in ids:
            ev = store.event(eid)
            if ev is None:
                continue
            row = ev.to_row()
            d = {k: row[k] for k in EVENT_FIELDS}
            d["details"] = ev.details
            d["file"] = files.get(ev.file_id, {}).get("rel_path", "")
            events[eid] = d
    # re-read and re-verify raw records, one pass per input file
    root = Path(manifest.get("input_dir", ""))
    by_file: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for d in events.values():
        by_file[d["file_id"]].append(d)
    for fid, evs in by_file.items():
        rel = evs[0]["file"]
        path = long_path(root / rel) if root and rel else None
        if path is None or not path.exists():
            for d in evs:
                d["raw"] = {"available": False, "note": "the original input file is not available at report time"}
            continue
        enc = detect_encoding(read_head(path))
        spans = [(d["line_start"], d["col_start"], d["line_end"], d["col_end"]) for d in evs]
        texts = read_spans(path, enc, spans)
        for d in evs:
            text = texts.get((d["line_start"], d["col_start"], d["line_end"], d["col_end"]))
            exact = d["details"].get("raw_exact", True)
            if text is None:
                d["raw"] = {"available": False, "note": "the recorded span is outside the file"}
                continue
            ok = sha256_text(text) == d["raw_sha256"] if exact else None
            d["raw"] = {
                "available": True,
                "text": text[:RAW_MAX_CHARS],
                "truncated": len(text) > RAW_MAX_CHARS,
                "verified": ok,
                "note": ("hash matches the hash recorded at ingest" if ok else
                         "HASH MISMATCH: the input file changed after ingest" if ok is False else
                         "item inside a wrapper object: the span covers the whole wrapper"),
                "encoding": enc.note,
            }
    return events


def executive_summary(case_p: dict[str, Any], cov: dict[str, Any], an: dict[str, Any]) -> dict[str, Any]:
    user = case_p.get("user", "")
    findings = an.get("findings", [])
    access = [f for f in findings if f["stage"] == "access" and LEVEL_RANK[f["level"]] >= 2]
    strong = [f for f in findings if LEVEL_RANK[f["level"]] >= 2]
    by_rule: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for f in strong:
        by_rule[f["rule_id"]].append(f)
    if access:
        first = min(access, key=lambda f: f.get("suspect_first_ts") or f["first_ts"])
        level = max((f["level"] for f in access), key=lambda lv: LEVEL_RANK[lv])
        ts = (first.get("suspect_first_ts") or first["first_ts"])[:16].replace("T", " ")
        ips = sorted({ip for f in access for ip in f["indicators"]["ips"]})
        headline = (f"The logs show attacker access to {user} from {ts} UTC ({level}), from "
                    f"{', '.join(ips[:4])}{' and others' if len(ips) > 4 else ''}.")
    elif strong:
        headline = f"The logs show suspicious activity on {user} at probable or confirmed level, but no sign-in could be identified as the attacker's."
    elif findings:
        headline = f"Only possible-level findings for {user}: leads to review, not conclusions."
    else:
        headline = f"No findings for {user} in the supplied logs."
    facts: list[str] = []

    def add(rule: str, text: str) -> None:
        if by_rule.get(rule):
            fs = by_rule[rule]
            lv = max((f["level"] for f in fs), key=lambda x: LEVEL_RANK[x])
            facts.append(f"{text} ({lv}; {', '.join(f['id'] for f in fs[:3])})")

    add("TT-SIGNIN-002", "Sign-ins in the account's name came from places too far apart to travel between")
    add("TT-SIGNIN-006", "A password was guessed after repeated failed sign-ins from the same address")
    add("TT-SIGNIN-004", "Mail was reached over a legacy protocol that cannot enforce MFA")
    add("TT-SIGNIN-005", "A sign-in succeeded with a password alone from an unfamiliar address")
    add("TT-AUTH-001", "An MFA method was added or changed during the attacker's access")
    add("TT-AUTH-002", "A device was registered to the account")
    add("TT-MAIL-001", "An inbox rule was created that hides, deletes or forwards mail")
    add("TT-MAIL-002", "Mailbox forwarding was configured")
    add("TT-MAIL-003", "Mailbox or folder permissions were granted")
    if by_rule.get("TT-MAIL-004") or by_rule.get("TT-MAIL-005"):
        fs = by_rule.get("TT-MAIL-004", []) + by_rule.get("TT-MAIL-005", [])
        lv = max((f["level"] for f in fs), key=lambda x: LEVEL_RANK[x])
        recs = sum(f["event_count"] for f in fs)
        facts.append(f"Mailbox content was read from attacker-linked sessions or addresses: {recs} mail access "
                     f"record(s) ({lv}); see the findings for the folders and message identifiers")
    add("TT-APP-001", "A user consented to an application with mail or file access")
    add("TT-APP-002", "The consented application then read mail")
    add("TT-FILE-001", "Files were downloaded in bulk from SharePoint or OneDrive")
    add("TT-FILE-002", "Documents were shared through anonymous or external links")
    pivot = an.get("pivot", [])
    if pivot:
        facts.append(f"{len(pivot)} other account(s) show the same attacker indicators: "
                     + ", ".join(p["account"] for p in pivot[:5]) + (" and others" if len(pivot) > 5 else ""))
    limits: list[str] = []
    for g in cov.get("gaps", []):
        rules = g.get("affects_rules") or []
        limits.append(f"{g['statement']} Likely cause: {g['likely_causes'][0] if g['likely_causes'] else 'unknown'}."
                      + (f" Checks with less to work on: {', '.join(rules)}." if rules else ""))
    na = [c for c in an.get("capability", []) if c["status"] == "not_assessable"]
    if na:
        limits.append("These checks could not be made with the supplied logs, so their absence of findings means "
                      "nothing: " + "; ".join(f"{c['rule_id']} ({c['title']}): {c['reasons'][0]}" for c in na))
    ipdb = an.get("ipdb")
    if ipdb and ipdb.get("events_enriched"):
        limits.append(f"Locations for {ipdb['events_enriched']} record(s) the logs gave no location for come from the "
                      f"analyst's offline IP database {Path(ipdb['file']).name} (SHA-256 {ipdb['sha256'][:16]}...), "
                      "not from Microsoft's logs; such records are marked 'ipdb' as their location source.")
    unverified = cov.get("reference", {}).get("unverified_entries", [])
    if unverified:
        limits.append("Some facts in the gap reference table are not yet verified against Microsoft documentation "
                      f"(entries: {', '.join(unverified)}); conclusions that rest on them are marked in the gap analysis.")
    next_steps = []
    for p in pivot[:5]:
        next_steps.append(f"Review {p['account']} ({p['strength']} indicator match: "
                          + ", ".join(f"{m['kind']} {m['value'][:40]}" for m in p["matches"][:3]) + ").")
    for g in cov.get("gaps", []):
        if g["kind"] in ("missing", "truncated", "ends_early", "quiet"):
            next_steps.append(f"Obtain {g['source_title']} for the case period, if they still exist.")
    window = an.get("window", {})
    return {"headline": headline, "facts": facts, "limits": limits, "next_steps": list(dict.fromkeys(next_steps)),
            "window": window, "counts": an.get("summary", {}).get("by_level", {})}


def build_report_data(case: Case) -> dict[str, Any]:
    manifest = case.read_json("manifest.json") or {}
    cov = case.read_json("coverage.json") or {}
    an = case.read_json("analysis.json") or {}
    params = case.params()
    events = load_events(case, manifest, _referenced(an))
    with CaseStore(case.db_path) as store:
        unrec = [{"file": f["rel_path"], "unrecognised": f["records_unrecognised"], "malformed": f["records_malformed"]}
                 for f in store.files() if f["records_unrecognised"] or f["records_malformed"]]
        reasons = [dict(zip(("reason", "count"), r)) for r in store.conn.execute(
            "SELECT reason, COUNT(*) FROM unrecognised GROUP BY reason ORDER BY 2 DESC LIMIT 20")]
        total_events = store.count()
    from tenanttrace.rules.engine import load_rules

    _, rules = load_rules()
    rule_meta = {r.id: {"title": r.title, "why": r.data["why"].strip(), "benign": r.data["benign"],
                        "attack": r.data["attack"], "kind": r.kind, "sources": r.sources_spec(),
                        "confidence": [{"level": c["level"], "reason": c["reason"]} for c in r.data["confidence"]]}
                 for r in rules}
    return {
        "report_format": REPORT_FORMAT,
        "generated_utc": utc_now_iso(),
        "tool": {"name": TOOL_NAME, "version": __version__, **(manifest.get("versions") or {})},
        "case": {
            "user": params.get("user", ""),
            "window": an.get("window", {}),
            "collected_at": cov.get("summary", {}).get("collected_at", ""),
            "collected_at_basis": cov.get("summary", {}).get("collected_at_basis", ""),
            "case_start": cov.get("summary", {}).get("case_start", ""),
            "case_end": cov.get("summary", {}).get("case_end", ""),
            "input_dir": manifest.get("input_dir", ""),
        },
        "summary": executive_summary(params, cov, an),
        "inputs": manifest.get("inputs", []),
        "totals": {**(manifest.get("totals") or {}), "events_stored": total_events},
        "linking": manifest.get("linking", {}),
        "unrecognised": {"files": unrec, "reasons": reasons},
        "coverage": {k: cov.get(k) for k in ("summary", "sources", "gaps", "lanes", "reference", "containers")},
        "capability": an.get("capability", []),
        "baseline": an.get("baseline", {}),
        "findings": an.get("findings", []),
        "timeline": an.get("timeline", {}),
        "pivot": an.get("pivot", []),
        "rules": rule_meta,
        "events": events,
    }
