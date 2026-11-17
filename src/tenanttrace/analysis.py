"""Analysis stage: baseline, detections, capability check, timeline and tenant pivot."""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Any

from tenanttrace.case import ProcessingLog
from tenanttrace.ingest.timeparse import fmt_utc, parse_user_time, parse_utc
from tenanttrace.rules.baseline import Baseline, build_baseline, span_days
from tenanttrace.rules.engine import LEVEL_RANK, Context, Engine, Finding, Rule, load_rules
from tenanttrace.schema import Event
from tenanttrace.store import CaseStore

ANCHOR_LOOKBACK = timedelta(hours=72)
DEFAULT_WINDOW_DAYS = 14


def _user_events(store: CaseStore, user: str) -> list[Event]:
    return list(store.query_events("actor = ? OR target = ?", (user, user)))


def estimate_window(params: dict[str, Any], events: list[Event], rules: list[Rule], coverage: dict[str, Any],
                    log: ProcessingLog) -> dict[str, Any]:
    """Decide where the suspected compromise window starts and say how it was decided."""
    if params.get("window_start"):
        ws = fmt_utc(parse_user_time(params["window_start"]))
        return {"start": ws, "method": "analyst", "basis": "supplied with --window-start"}
    # Anchors: baseline-independent rules flagged `anchor: true`, evaluated with an empty baseline.
    empty = Context(user=params["user"], window_start="0000", baseline=Baseline(), tenant_domains=set(),
                    session_countries=_session_countries(events), ip_failed_users={})
    eng = Engine(rules, empty, events)
    anchors: list[tuple[str, str, str]] = []
    for r in rules:
        if not r.data.get("anchor"):
            continue
        for f in eng.run_rule(r):
            anchors.append((f.first_ts, r.id, f.events[0].event_id))
    if anchors:
        anchors.sort()
        t0 = parse_utc(anchors[0][0]) - ANCHOR_LOOKBACK
        return {"start": fmt_utc(t0), "method": "estimated",
                "basis": f"earliest baseline-independent indicator ({anchors[0][1]} at {anchors[0][0]}) "
                         f"minus {int(ANCHOR_LOOKBACK.total_seconds() // 3600)} hours",
                "anchor_event": anchors[0][2], "anchor_rule": anchors[0][1]}
    end = params.get("collected_at") or coverage.get("summary", {}).get("collected_at") or (
        events[-1].ts_utc if events else "")
    if not end:
        return {"start": "", "method": "none", "basis": "no events for this account"}
    t0 = parse_user_time(end) - timedelta(days=DEFAULT_WINDOW_DAYS)
    return {"start": fmt_utc(t0), "method": "default",
            "basis": f"no anchor indicator found; the last {DEFAULT_WINDOW_DAYS} days before collection"}


REPLAY_MAX_KMH = 900.0
REPLAY_NO_COORDS_MINUTES = 60


def _session_countries(events: list[Event]) -> dict[str, set[str]]:
    """Sessions whose own sign-ins could not come from one device: the countries involved.

    A session used in two countries is normal for a traveller (days apart). It is treated as
    replayed only when consecutive successful sign-ins in the session imply travel faster than
    an airliner, or, when the logs carry no coordinates, two countries within an hour.
    """
    from tenanttrace.rules.engine import haversine

    by_session: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.category == "signin" and e.session_id and e.geo_country and e.outcome == "success":
            by_session[e.session_id].append(e)
    out: dict[str, set[str]] = {}
    for sid, evs in by_session.items():
        evs.sort(key=lambda x: (x.ts_utc, x.event_id))
        for a, b in zip(evs, evs[1:]):
            if a.geo_country.upper() == b.geo_country.upper():
                continue
            hours = (parse_utc(b.ts_utc) - parse_utc(a.ts_utc)).total_seconds() / 3600
            if None not in (a.geo_lat, a.geo_lon, b.geo_lat, b.geo_lon):
                km = haversine(a.geo_lat, a.geo_lon, b.geo_lat, b.geo_lon)
                replay = km / max(hours, 1 / 60) > REPLAY_MAX_KMH
            else:
                replay = hours * 60 <= REPLAY_NO_COORDS_MINUTES
            if replay:
                out.setdefault(sid, set()).update({a.geo_country.upper(), b.geo_country.upper()})
    return out


def _tenant_domains(store: CaseStore) -> set[str]:
    doms = set()
    for (actor,) in store.conn.execute("SELECT DISTINCT actor FROM events WHERE actor LIKE '%@%'"):
        doms.add(actor.rsplit("@", 1)[1].lower())
    return doms


def _ip_failed_users(store: CaseStore) -> dict[str, set[str]]:
    out: dict[str, set[str]] = defaultdict(set)
    for ip, actor in store.conn.execute(
            "SELECT ip, actor FROM events WHERE category='signin' AND outcome='failure' AND ip != ''"):
        out[ip].add(actor)
    return out


# ----------------------------------------------------------------------------- capability


def rule_capability(rule: Rule, coverage: dict[str, Any], baseline: Baseline, window: dict[str, Any],
                    user_events: list[Event]) -> dict[str, Any]:
    """Could the supplied data have shown what this rule looks for?

    A source counts as usable when it was supplied: either it has records, or it is a sparse
    source inside an export that was supplied (no inbox-rule cmdlet records simply means none
    were run). A source that is missing, or whose auditing appears to be absent, is not usable.
    """
    rows = {s["source"]: s for s in coverage.get("sources", [])}
    usable = {sid for sid, r in rows.items() if r.get("status") in ("present", "no_records")}
    spec = rule.sources_spec()
    needed_all = list(spec.get("all", []))
    needed_any = list(spec.get("any", []))
    reasons: list[str] = []
    caveats: list[str] = []
    status = "assessed"

    def why_not(sid: str) -> str:
        st = rows.get(sid, {}).get("status", "missing")
        if st == "auditing_absent":
            return f"{sid} (the export is present but holds none of these records: auditing appears to be off)"
        return f"{sid} (not supplied)"

    missing_all = [s for s in needed_all if s not in usable]
    have_any = [s for s in needed_any if s in usable]
    if missing_all:
        status = "not_assessable"
        reasons.append("required log source unavailable: " + "; ".join(why_not(s) for s in missing_all))
    if needed_any and not have_any:
        status = "not_assessable"
        reasons.append("none of the log sources that record this are available: "
                       + "; ".join(why_not(s) for s in needed_any))
    used = [rows[s] for s in needed_all + have_any if s in rows]
    ws = window.get("start", "")
    if status == "assessed" and ws and used:
        if all((u.get("covers_last") or "") < ws for u in used):
            status = "not_assessable"
            reasons.append("the supplied logs for this end before the compromise window starts ("
                           + ", ".join(f"{u['source']} ends {(u.get('covers_last') or '')[:10]}" for u in used) + ")")
        else:
            late = [u for u in used if (u.get("covers_first") or "") > ws]
            if late:
                caveats.append("the early part of the compromise window is not covered: "
                               + ", ".join(f"{u['source']} starts {u['covers_first'][:16]}Z" for u in late))
    for g in coverage.get("gaps", []):
        if status != "not_assessable" and rule.id in g.get("affects_rules", []) and g["kind"] in (
                "truncated", "ends_early", "quiet", "retention"):
            caveats.append(f"{g['kind'].replace('_', ' ')} gap in {g['source']} ({(g.get('start') or '')[:10]} to "
                           f"{(g.get('end') or '')[:10]})")
    need_days = rule.data.get("needs_baseline_days")
    if status != "not_assessable" and need_days:
        kind = rule.data.get("baseline_kind", "any")
        first = baseline.signin_start if kind == "signin" else baseline.start
        count = baseline.signin_events if kind == "signin" else baseline.events
        span = span_days(first, baseline.end) if first and baseline.end and baseline.end != "9999" else 0.0
        need_events = int(rule.data.get("needs_baseline_events", 10))
        what = "successful sign-ins" if kind == "signin" else "records"
        if span < float(need_days) or count < need_events:
            status = "not_assessable"
            reasons.append(f"the account's {what} before the compromise window reach back {span:.1f} day(s) "
                           f"({count} record(s)); this rule needs at least {need_days} days and {need_events} "
                           "records of history to say what is unusual for the account")
    for fld in rule.data.get("needs_fields", []):
        if status == "not_assessable":
            break
        cat = rule.data.get("field_category")
        cands = [e for e in user_events if not cat or e.category == cat]
        if cands and not any(getattr(e, fld, None) not in (None, "") for e in cands):
            status = "not_assessable"
            reasons.append(f"none of the supplied {cat or ''} records carry {fld}"
                           + (" (the Entra CSV download has no coordinates; the JSON download does)"
                              if fld == "geo_lat" else ""))
    if status == "assessed" and caveats:
        status = "partial"
    return {"rule_id": rule.id, "title": rule.title, "status": status, "reasons": reasons + caveats,
            "sources_needed": needed_all + needed_any,
            "sources_available": [s for s in needed_all + needed_any if s in usable]}


# ----------------------------------------------------------------------------- run


def run_analysis(store: CaseStore, params: dict[str, Any], coverage: dict[str, Any], log: ProcessingLog) -> dict[str, Any]:
    from tenanttrace.timeline import build_timeline
    from tenanttrace.pivot import tenant_pivot

    user = params["user"].lower()
    version, rules = load_rules()
    events = _user_events(store, user)
    log.write("analyze", f"{len(events)} event(s) involve {user}", ruleset=version, rules=len(rules))
    window = estimate_window(params, events, rules, coverage, log)
    log.write("analyze", f"compromise window start {window.get('start') or 'n/a'} ({window['method']})",
              window=window)
    ws = window.get("start") or "9999"
    baseline = build_baseline(events, ws)
    ctx = Context(user=user, window_start=ws, baseline=baseline, tenant_domains=_tenant_domains(store),
                  session_countries=_session_countries(events), ip_failed_users=_ip_failed_users(store))

    def tenant_events():
        return store.query_events("category='signin'")

    eng = Engine(rules, ctx, events, tenant_events=tenant_events)
    capability = []
    findings: list[Finding] = []
    by_rule: dict[str, list[Finding]] = {}
    access_ok = True
    for stage in ("access", "post"):
        if stage == "post":
            access_ok = any(c["status"] in ("assessed", "partial") for c in capability
                            if c["rule_id"] in {r.id for r in rules if r.stage == "access"})
        for r in rules:
            if r.stage != stage:
                continue
            cap = rule_capability(r, coverage, baseline, window, events)
            if r.data.get("depends_on_access") and not access_ok and cap["status"] != "not_assessable":
                cap["status"] = "not_assessable"
                cap["reasons"].append("this rule links activity to sign-ins already assessed as attacker access, "
                                      "and no sign-in rule could be assessed with the supplied logs")
            if cap["status"] == "not_assessable":
                capability.append({**cap, "findings": 0})
                log.write("rule", f"{r.id} could not be assessed: {'; '.join(cap['reasons'])}")
                continue
            fs = eng.run_rule(r)
            by_rule[r.id] = fs
            findings.extend(fs)
            capability.append({**cap, "findings": len(fs)})
            log.write("rule", f"{r.id} assessed: {len(fs)} finding(s)")
        if stage == "access":
            for f in findings:
                ind = f.indicators()
                ctx.suspect_ips.update(i for i in ind["ips"] if i not in baseline.ips)
                if LEVEL_RANK[f.level] >= 2:
                    ctx.flagged_ips.update(i for i in ind["ips"] if i not in baseline.ips)
                    ctx.flagged_sessions.update(_attacker_sessions(f, baseline))
                    ctx.flagged_tokens.update(ind["token_ids"])
                    ctx.flagged_uas.update(ind["user_agents"])
            # second pass over access rules so that their own grading can use the flags
            for f in findings:
                eng._grade(f)
        if stage == "post":
            pass
    for f in findings:
        if f.rule.data.get("flags_app"):
            ctx.flagged_apps.update(f.indicators()["app_ids"] or [str(e.details.get("app_id", "")).lower() for e in f.events])
    # rules that depend on flagged apps run last
    for r in rules:
        if r.stage == "late":
            cap = rule_capability(r, coverage, baseline, window, events)
            if cap["status"] == "not_assessable":
                capability.append({**cap, "findings": 0})
                continue
            fs = eng.run_rule(r)
            findings.extend(fs)
            capability.append({**cap, "findings": len(fs)})
            log.write("rule", f"{r.id} assessed: {len(fs)} finding(s)")

    fj = sorted((f.to_json() for f in findings), key=lambda x: (x["first_ts"], x["rule_id"], x["id"]))
    # keep only one finding per id (identical evidence)
    seen: set[str] = set()
    unique = []
    for f in fj:
        if f["id"] in seen:
            continue
        seen.add(f["id"])
        unique.append(f)
    timeline = build_timeline(store, user, unique, window, ctx)
    pivot = tenant_pivot(store, user, unique, baseline)
    capability.sort(key=lambda c: c["rule_id"])
    counts = defaultdict(int)
    for f in unique:
        counts[f["level"]] += 1
    summary = {
        "user": user,
        "findings": len(unique),
        "by_level": dict(sorted(counts.items())),
        "rules_not_assessable": [c["rule_id"] for c in capability if c["status"] == "not_assessable"],
        "rules_partial": [c["rule_id"] for c in capability if c["status"] == "partial"],
        "pivot_accounts": [p["account"] for p in pivot],
        "window_start": window.get("start"),
        "window_method": window.get("method"),
    }
    return {
        "summary": summary,
        "ruleset_version": version,
        "window": window,
        "baseline": baseline.to_json(),
        "findings": unique,
        "capability": capability,
        "timeline": timeline,
        "pivot": pivot,
        "baseline_span_days": round(span_days(baseline.start, ws), 1) if baseline.start else 0,
    }


def _attacker_sessions(f: Finding, baseline: Baseline) -> set[str]:
    """Session ids of a flagged access finding, excluding sessions established in the baseline."""
    out = set()
    for e in f.suspect_events():
        if e.session_id and e.ts_utc >= baseline.end:
            out.add(e.session_id)
    return out
