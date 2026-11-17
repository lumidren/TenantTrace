"""Evidence coverage and gap analysis.

For every log source in the gap reference table this works out whether it was supplied, which
period it covers (tenant-wide and for the account under investigation), and whether it shows
signs of being missing, truncated, cut short by retention, quiet for an unexplained period, or
present without the auditing that should populate it. Each gap carries its likely causes,
reasoned from the reference table, with the table entries and documentation it relied on.

Sources live in containers. Every `ual_*` source comes from a unified audit log export, so the
period a UAL export covers is the period for all of them: an export that covers October but has
no MailItemsAccessed records says something about mailbox auditing, not about the export. Entra
sign-in and audit sources are their own containers.

"Unexplained" silence is judged against each source's own rhythm. For every source (and for
the UAL export as a whole) TenantTrace learns how many records it normally produces in each
hour of a weekday and of a weekend day, and only calls a silent stretch a gap when that rhythm
predicts a meaningful number of records for it while the other sources kept their usual pace.
Nights, weekends and tenant-wide quiet days are therefore not reported.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from tenanttrace.case import ProcessingLog
from tenanttrace.coverage.reference import load_reference
from tenanttrace.hashing import short_id
from tenanttrace.ingest.timeparse import fmt_utc, parse_user_time, parse_utc
from tenanttrace.store import CaseStore

QUIET_MIN_HOURS = 6
MIN_EXPECTED_RECORDS = 10.0      # a silence is only evidence if the source's rhythm predicts this many
OTHERS_ACTIVE_RATIO = 0.5        # other sources must show at least half their usual volume meanwhile
RETENTION_TOLERANCE_DAYS = 1.5

_KIND_ORDER = {"missing": 0, "auditing_absent": 1, "truncated": 2, "ends_early": 3, "retention": 4,
               "quiet": 5, "user_absent": 6, "filtered": 7}
ACTIVE = "(link_role IS NULL OR link_role != 'duplicate')"


def _days(a: str, b: str) -> float:
    return (parse_utc(b) - parse_utc(a)).total_seconds() / 86400.0


def _floor_hour(ts: str) -> datetime:
    return parse_utc(ts).replace(minute=0, second=0, microsecond=0)


class Rhythm:
    """Hour-of-day profile of one series (separately for weekdays and weekends)."""

    def __init__(self, hourly: dict[str, int], first: str, last: str):
        self.hourly = hourly
        self.first = _floor_hour(first)
        self.last = _floor_hour(last)
        totals: dict[tuple[bool, int], int] = defaultdict(int)
        slots: dict[tuple[bool, int], int] = defaultdict(int)
        t = self.first
        while t <= self.last:
            key = (t.weekday() >= 5, t.hour)
            slots[key] += 1
            totals[key] += hourly.get(t.strftime("%Y-%m-%dT%H"), 0)
            t += timedelta(hours=1)
        self.rate = {k: totals[k] / slots[k] for k in slots if slots[k]}

    def expected(self, start: datetime, end: datetime) -> float:
        total = 0.0
        t = start
        while t < end:
            total += self.rate.get((t.weekday() >= 5, t.hour), 0.0)
            t += timedelta(hours=1)
        return total

    def observed(self, start: datetime, end: datetime) -> int:
        n = 0
        t = start
        while t < end:
            n += self.hourly.get(t.strftime("%Y-%m-%dT%H"), 0)
            t += timedelta(hours=1)
        return n


def compute_coverage(store: CaseStore, params: dict[str, Any], log: ProcessingLog) -> dict[str, Any]:
    ref = load_reference()
    user = (params.get("user") or "").lower()
    stats = {r[0]: {"events": r[1], "first": r[2], "last": r[3], "actors": r[4]} for r in store.conn.execute(
        f"SELECT source, COUNT(*), MIN(ts_utc), MAX(ts_utc), COUNT(DISTINCT actor) FROM events WHERE {ACTIVE} "
        "GROUP BY source")}
    ustats = {r[0]: {"events": r[1], "first": r[2], "last": r[3]} for r in store.conn.execute(
        f"SELECT source, COUNT(*), MIN(ts_utc), MAX(ts_utc) FROM events WHERE (actor = ? OR target = ?) AND {ACTIVE} "
        "GROUP BY source", (user, user))}
    files = store.files()

    # containers: the period each export covers, from the files that were parsed
    containers: dict[str, dict[str, Any]] = {}
    for f in files:
        info = f.get("info") or {}
        c = info.get("container")
        if not c or not f.get("records_parsed"):
            continue
        cr = containers.setdefault(c, {"first": "", "last": "", "files": [], "truncation": []})
        if info.get("first") and (not cr["first"] or info["first"] < cr["first"]):
            cr["first"] = info["first"]
        if info.get("last") and info["last"] > cr["last"]:
            cr["last"] = info["last"]
        cr["files"].append(f["rel_path"])
        for t in info.get("truncation") or []:
            cr["truncation"].append({**t, "file": f["rel_path"]})

    all_first = min((s["first"] for s in stats.values() if s["events"]), default="")
    all_last = max((s["last"] for s in stats.values() if s["events"]), default="")
    if params.get("collected_at"):
        collected = fmt_utc(parse_user_time(params["collected_at"]))
        collected_basis = "supplied with --collected-at"
    else:
        collected = all_last
        collected_basis = "latest event in any input (no --collected-at given)"
    case_start = all_first

    # rhythms: one per non-UAL source and one for the UAL export as a whole
    hourly: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for source, hour, n in store.conn.execute(
            f"SELECT source, substr(ts_utc, 1, 13), COUNT(*) FROM events WHERE {ACTIVE} GROUP BY 1, 2"):
        series = "ual" if source.startswith("ual_") else source
        hourly[series][hour] += n
    rhythms: dict[str, Rhythm] = {}
    for series, h in hourly.items():
        first = containers["ual"]["first"] if series == "ual" and "ual" in containers else min(
            f"{k}:00:00.000000Z" for k in h)
        last = containers["ual"]["last"] if series == "ual" and "ual" in containers else max(
            f"{k}:00:00.000000Z" for k in h)
        rhythms[series] = Rhythm(h, first, last)

    # pass 1: status of every reference source
    rows: dict[str, dict[str, Any]] = {}
    for entry in ref.sources:
        sid = entry["id"]
        st = stats.get(sid, {"events": 0, "first": "", "last": "", "actors": 0})
        ust = ustats.get(sid, {"events": 0, "first": "", "last": ""})
        cont = entry.get("container", sid)
        in_ual = cont == "ual"
        cr = containers.get("ual") if in_ual else None
        supplied = (cr is not None) if in_ual else st["events"] > 0
        if not supplied:
            status = "missing"
        elif st["events"] > 0:
            status = "present"
        elif entry.get("activity") == "continuous":
            status = "auditing_absent"
        else:
            status = "no_records"
        rows[sid] = {
            "source": sid,
            "title": entry["title"],
            "container": cont,
            "status": status,
            "events": st["events"],
            "first": st["first"],
            "last": st["last"],
            "covers_first": (cr["first"] if cr else st["first"]) if supplied else "",
            "covers_last": (cr["last"] if cr else st["last"]) if supplied else "",
            "user_events": ust["events"],
            "user_first": ust["first"],
            "user_last": ust["last"],
            "accounts": st["actors"],
            "activity": entry.get("activity", "continuous"),
            "expected": entry.get("expected", "recommended"),
            "files": sorted(cr["files"]) if cr else sorted({f["rel_path"] for f in files
                                                            if sid in ((f.get("info") or {}).get("sources") or [])}),
            "verified": bool(entry.get("verified")),
            "unverified": entry.get("unverified", []),
            "retention": entry.get("retention", {}),
            "licence": entry.get("licence", ""),
            "default_on": entry.get("default_on", ""),
            "records": " ".join(str(entry.get("records", "")).split()),
        }
    for entry in ref.sources:
        rows[entry["id"]]["alternatives_supplied"] = [
            a for a in entry.get("alternatives", []) if rows.get(a, {}).get("status") in ("present", "no_records")]

    # pass 2: gaps
    gaps: list[dict[str, Any]] = []
    for entry in ref.sources:
        sid = entry["id"]
        row = rows[sid]
        cites = ref.cite(sid)
        status = row["status"]
        if status == "missing":
            if entry.get("expected") == "optional" or row["alternatives_supplied"]:
                continue
            gaps.append(_gap(entry, "missing", case_start, collected, f"{entry['title']} were not supplied.",
                             ["the export was not collected or not supplied"] + list(entry.get("missing_causes", [])),
                             cites))
            continue
        if status == "auditing_absent":
            siblings = sorted(s for s, v in stats.items() if v["events"] and s.startswith("ual_"))
            gaps.append(_gap(entry, "auditing_absent", row["covers_first"], row["covers_last"],
                             f"{entry['title']}: no records at all, although the same audit log export holds "
                             f"{sum(stats[s]['events'] for s in siblings):,} other records "
                             f"({', '.join(siblings)}). Active mailboxes produce these records every working day.",
                             list(entry.get("absent_causes", [])) or [
                                 "auditing for these record types was not enabled",
                                 "the licence does not include these record types",
                                 "the export was filtered to exclude them"], cites))
            continue
        if status != "present" or row["container"] == "ual":
            continue  # UAL sources share the export's period: judged once, at container level below
        rh = rhythms.get(sid)
        g = _retention_gap(entry, row["covers_first"], collected, case_start, rh, cites)
        if g:
            gaps.append(g)
        g = _ends_early(entry, row["covers_last"], collected, rh, cites)
        if g:
            gaps.append(g)
    for entry in ref.sources:
        row = rows[entry["id"]]
        if (user and row["status"] == "present" and not row["user_events"]
                and entry.get("activity") == "continuous"):
            gaps.append(_gap(entry, "user_absent", row["covers_first"], row["covers_last"],
                             f"{entry['title']} are present for {row['accounts']} account(s) but not for {user}.",
                             ["the account is excluded from auditing (for example an audit bypass association)",
                              "the account is not licensed for these records",
                              "the account did not use this service in the period",
                              "the export was filtered to other accounts"], ref.cite(entry["id"])))

    # the unified audit log export as a whole
    ual = containers.get("ual")
    if ual is not None:
        affected = [s for s, r in rows.items() if r["container"] == "ual" and r["status"] != "missing"]
        pseudo = {"id": "ual", "title": "Unified audit log export", "verified": True}
        cites_ual = ref.cite("ual_exchange_admin")
        for t in ual["truncation"]:
            gaps.append(_gap(pseudo, "truncated", t.get("after") or ual["last"], collected,
                             f"{t['file']}: {t['evidence']}.", t.get("causes", []), cites_ual,
                             affects_sources=affected, file=t["file"]))
        rh = rhythms.get("ual")
        g = _retention_gap(pseudo, ual["first"], collected, case_start, rh, cites_ual,
                           options=ref.entry("ual_exchange_admin").get("retention", {}).get("options", []))
        if g:
            g["affects_sources"] = affected
            gaps.append(g)
        g = _ends_early(pseudo, ual["last"], collected, rh, cites_ual)
        if g:
            g["affects_sources"] = affected
            gaps.append(g)
        n_actors = store.conn.execute(
            f"SELECT COUNT(DISTINCT actor) FROM events WHERE source LIKE 'ual_%' AND {ACTIVE} AND actor LIKE '%@%'"
        ).fetchone()[0]
        n_users = store.conn.execute("SELECT COUNT(DISTINCT actor) FROM events WHERE actor LIKE '%@%'").fetchone()[0]
        if n_actors == 1 and n_users > 1:
            gaps.append(_gap(pseudo, "filtered", ual["first"], ual["last"],
                             "The unified audit log export contains records for one account only.",
                             ["the export was filtered by user (for example Search-UnifiedAuditLog -UserIds)"],
                             cites_ual, affects_sources=affected,
                             effect="the tenant pivot cannot use the audit log to find other affected accounts"))
    for c, cr in containers.items():
        if c == "ual":
            continue
        for t in cr["truncation"]:
            srcs = [s for s, r in rows.items() if s.startswith(c) and r["status"] == "present"] or [c]
            entry = ref.entry(srcs[0]) if ref.has(srcs[0]) else {"id": c, "title": c, "verified": False}
            gaps.append(_gap(entry, "truncated", t.get("after") or cr["last"], collected,
                             f"{t['file']}: {t['evidence']}.", t.get("causes", []), ref.cite(entry["id"]),
                             affects_sources=srcs, file=t["file"]))

    gaps.extend(_quiet_periods(rhythms, rows, ref))
    for g in gaps:
        srcs = g.get("affects_sources") or [g["source"]]
        g["affects_rules"] = sorted({r for s in srcs for r in ref.rules_for(s)})
    gaps.sort(key=lambda g: (_KIND_ORDER.get(g["kind"], 9), g["source"], g.get("start") or ""))
    for g in gaps:
        g["id"] = "G-" + short_id(g["source"], g["kind"], g.get("start") or "", g.get("end") or "", length=8)

    sources_out = [rows[e["id"]] for e in ref.sources]
    summary = {
        "case_start": case_start,
        "case_end": all_last,
        "collected_at": collected,
        "collected_at_basis": collected_basis,
        "sources_present": sorted(s["source"] for s in sources_out if s["status"] in ("present", "no_records")),
        "sources_missing": sorted(s["source"] for s in sources_out if s["status"] == "missing"),
        "sources_auditing_absent": sorted(s["source"] for s in sources_out if s["status"] == "auditing_absent"),
        "sources_unmapped": sorted(s for s in stats if not ref.has(s)),
        "gap_count": len(gaps),
        "gap_kinds": sorted({g["kind"] for g in gaps}),
        "user": user,
        "user_events": sum(v["events"] for v in ustats.values()),
    }
    log.write("coverage", f"{len(summary['sources_present'])} source(s) supplied, {len(gaps)} gap(s): "
                          + (", ".join(f"{g['kind']}:{g['source']}" for g in gaps) or "none"))
    return {
        "summary": summary,
        "sources": sources_out,
        "containers": {c: cr for c, cr in sorted(containers.items())},
        "gaps": gaps,
        "lanes": _lanes(store, case_start, collected or all_last),
        "reference": {
            "version": ref.version,
            "title": ref.title,
            "unverified_entries": [e["id"] for e in ref.sources if not e.get("verified")],
            "entries": {e["id"]: {k: e.get(k) for k in ("title", "licence", "retention", "default_on", "citations",
                                                         "last_checked", "verified", "unverified")}
                        for e in ref.sources},
        },
    }


def _gap(entry: dict[str, Any], kind: str, start: str, end: str, statement: str, causes: list[str],
         citations: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    return {"source": entry["id"], "source_title": entry["title"], "kind": kind, "start": start, "end": end,
            "statement": statement, "likely_causes": causes, "citations": citations,
            "reference_verified": bool(entry.get("verified")), **extra}


def _retention_gap(entry: dict[str, Any], first: str, collected: str, case_start: str, rh: Rhythm | None,
                   cites: list[dict[str, Any]], options: list[dict[str, Any]] | None = None) -> dict[str, Any] | None:
    """The source starts later than the case; its own rhythm says records should exist before that."""
    if not first or not collected or not case_start or first <= case_start:
        return None
    expected = rh.expected(_floor_hour(case_start), _floor_hour(first)) if rh else 0.0
    if expected < MIN_EXPECTED_RECORDS:
        return None
    reach = _days(first, collected)
    late = _days(case_start, first)
    coll = parse_utc(collected)
    for opt in options if options is not None else entry.get("retention", {}).get("options", []):
        days = float(opt["days"])
        cutoff = coll - timedelta(days=days)
        # the retention cut-off sits somewhere before the first surviving record; it matches when the
        # first record is no earlier than the cut-off and the source's rhythm predicts (almost) no
        # records between the cut-off and that first record
        if reach > days + RETENTION_TOLERANCE_DAYS:
            continue
        between = rh.expected(cutoff.replace(minute=0, second=0, microsecond=0), _floor_hour(first)) if rh else 0.0
        if between < MIN_EXPECTED_RECORDS:
            return _gap(entry, "retention", case_start, first,
                        f"{entry['title']} reach back only {reach:.1f} days before collection and start {late:.1f} "
                        f"days after the earliest record in other sources (about {expected:.0f} records would be "
                        f"expected in that span). {int(days)} days is the retention of {opt['applies_to']}.",
                        [f"retention limit: {opt['applies_to']} keeps these records for {int(days)} days",
                         "the export's start date was set later than for the other sources"],
                        cites, retention_days=int(days), licence_hint=opt["applies_to"], expected_records=round(expected))
    return _gap(entry, "retention", case_start, first,
                f"{entry['title']} start {late:.1f} days later than the earliest record in other sources (about "
                f"{expected:.0f} records would be expected in that span); the reach of {reach:.1f} days before "
                "collection matches no retention period in the reference table.",
                ["the export's start date was set later than for the other sources",
                 "a retention limit not listed in the reference table"], cites, expected_records=round(expected))


def _ends_early(entry: dict[str, Any], last: str, collected: str, rh: Rhythm | None,
                cites: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not last or not collected or last >= collected:
        return None
    start = _floor_hour(last) + timedelta(hours=1)
    expected = rh.expected(start, _floor_hour(collected)) if rh else 0.0
    if expected < MIN_EXPECTED_RECORDS:
        return None
    hours = (parse_utc(collected) - parse_utc(last)).total_seconds() / 3600
    return _gap(entry, "ends_early", last, collected,
                f"{entry['title']} end at {last[:16]}Z, {hours:.0f} hours before collection; the source's own "
                f"rhythm predicts about {expected:.0f} records after that point.",
                ["the export's end date was set too early",
                 "the export hit a size or row limit, so later records were not written",
                 "audit ingestion latency at collection time (typically 60-90 minutes for core services)"],
                cites, expected_records=round(expected))


def _quiet_periods(rhythms: dict[str, Rhythm], rows: dict[str, dict[str, Any]], ref) -> list[dict[str, Any]]:
    out = []
    for series, rh in sorted(rhythms.items()):
        if series == "ual":
            entry = {"id": "ual", "title": "Unified audit log export", "verified": True}
            cites = ref.cite("ual_exchange_admin")
            affected = [s for s, r in rows.items() if r["container"] == "ual" and r["status"] == "present"]
        else:
            if series not in rows or rows[series]["activity"] != "continuous":
                continue
            entry = ref.entry(series)
            cites = ref.cite(series)
            affected = [series]
        t = rh.first
        run_start = None
        runs = []
        while t <= rh.last:
            if rh.hourly.get(t.strftime("%Y-%m-%dT%H"), 0) == 0:
                run_start = run_start or t
            elif run_start is not None:
                runs.append((run_start, t))
                run_start = None
            t += timedelta(hours=1)
        for a, b in runs:
            hours = int((b - a).total_seconds() // 3600)
            if hours < QUIET_MIN_HOURS:
                continue
            exp_self = rh.expected(a, b)
            if exp_self < MIN_EXPECTED_RECORDS:
                continue   # the source is normally quiet at these hours
            others = [(s, o) for s, o in rhythms.items() if s != series]
            exp_other = sum(o.expected(a, b) for _, o in others)
            obs_other = sum(o.observed(a, b) for _, o in others)
            if exp_other < MIN_EXPECTED_RECORDS or obs_other < OTHERS_ACTIVE_RATIO * exp_other:
                continue   # everything was quiet: not evidence of a gap in this source
            busiest = sorted(((o.observed(a, b), s) for s, o in others), reverse=True)[:3]
            g = _gap(entry, "quiet", fmt_utc(a), fmt_utc(b),
                     f"{entry['title']}: no records for {hours} hours, where its own rhythm predicts about "
                     f"{exp_self:.0f}; meanwhile other sources recorded {obs_other:,} events (about {exp_other:.0f} "
                     f"usual): " + ", ".join(f"{s} {n:,}" for n, s in busiest if n) + ".",
                     ["records missing from the export for this period (a failed or partial export page)",
                      "an audit pipeline outage or ingestion delay at the time",
                      "auditing switched off and back on"],
                     cites, hours=hours, expected_records=round(exp_self), affects_sources=affected)
            out.append(g)
    return out


def _lanes(store: CaseStore, start: str, end: str) -> dict[str, Any]:
    """Daily counts per source for the coverage chart (aggregated; no event detail)."""
    days: dict[str, dict[str, int]] = defaultdict(dict)
    for source, day, n in store.conn.execute(
            f"SELECT source, substr(ts_utc, 1, 10), COUNT(*) FROM events WHERE {ACTIVE} GROUP BY 1, 2"):
        days[source][day] = n
    return {"start": start[:10], "end": end[:10], "bucket": "day",
            "series": {s: dict(sorted(d.items())) for s, d in sorted(days.items())}}
