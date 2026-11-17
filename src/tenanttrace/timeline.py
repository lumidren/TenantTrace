"""Account timeline: one chronological story for the compromised account.

Every step carries a label:

  observed   the statement is read directly from log records (the step lists them)
  inference  the statement goes beyond the records; `basis` says what it rests on

Session linking ties activity to the sign-in that produced it. A link through a session or
token identifier present in both records is observed. A link through IP address and time
proximity is an inference, and is labelled so.
"""

from __future__ import annotations

from bisect import bisect_right
from collections import defaultdict
from typing import Any

from tenanttrace.hashing import short_id
from tenanttrace.ingest.timeparse import parse_utc
from tenanttrace.schema import Event
from tenanttrace.store import CaseStore

IP_LINK_HOURS = 12


class SessionLinker:
    def __init__(self, signins: list[Event]):
        self.by_session: dict[str, list[Event]] = defaultdict(list)
        self.by_token: dict[str, Event] = {}
        self.by_ip: dict[str, list[Event]] = defaultdict(list)
        for s in sorted(signins, key=lambda e: (e.ts_utc, e.event_id)):
            if s.outcome != "success":
                continue
            if s.session_id:
                self.by_session[s.session_id].append(s)
            if s.token_id:
                self.by_token.setdefault(s.token_id, s)
            if s.ip:
                self.by_ip[s.ip].append(s)

    @staticmethod
    def _latest_before(cands: list[Event], ts: str) -> Event | None:
        keys = [c.ts_utc for c in cands]
        i = bisect_right(keys, ts)
        if i:
            return cands[i - 1]
        return cands[0] if cands else None

    def link(self, ev: Event) -> dict[str, Any]:
        if ev.category == "signin":
            return {"method": "self", "label": "observed", "text": "this is a sign-in record"}
        if ev.token_id and ev.token_id in self.by_token:
            s = self.by_token[ev.token_id]
            return {"method": "token_id", "label": "observed", "signin_event_id": s.event_id,
                    "text": f"token identifier recorded in both this record and the sign-in at {s.ts_utc[:19]}Z from {s.ip}"}
        if ev.session_id and ev.session_id in self.by_session:
            s = self._latest_before(self.by_session[ev.session_id], ev.ts_utc)
            if s is not None:
                return {"method": "session_id", "label": "observed", "signin_event_id": s.event_id,
                        "text": f"session ID recorded in both this record and the sign-in at {s.ts_utc[:19]}Z from {s.ip}"}
        if ev.ip and ev.ip.split(":")[0] in self.by_ip or ev.ip in self.by_ip:
            cands = self.by_ip.get(ev.ip) or self.by_ip.get(ev.ip.split(":")[0], [])
            s = self._latest_before(cands, ev.ts_utc)
            if s is not None and s.ts_utc <= ev.ts_utc:
                hours = (parse_utc(ev.ts_utc) - parse_utc(s.ts_utc)).total_seconds() / 3600
                if hours <= IP_LINK_HOURS:
                    why = "no session or token identifier in this record" if not (ev.session_id or ev.token_id) \
                        else "its session identifier does not appear in any supplied sign-in record"
                    return {"method": "ip_time", "label": "inference", "signin_event_id": s.event_id,
                            "text": f"same IP address as the sign-in {hours:.1f} h earlier; {why}"}
        return {"method": "none", "label": "inference",
                "text": "no supplied sign-in record can be linked to this activity"}


PHASE_ORDER = {"initial_access": 0, "credential_access": 0, "persistence": 1, "defense_evasion": 2,
               "collection": 3, "exfiltration": 4, "impact": 5, "other": 6}


def build_timeline(store: CaseStore, user: str, findings: list[dict[str, Any]], window: dict[str, Any],
                   ctx: Any) -> dict[str, Any]:
    from tenanttrace.rules.engine import load_rules

    _, rules = load_rules()
    phase_of = {r.id: r.data.get("phase", "other") for r in rules}
    signins = list(store.query_events("actor = ? AND category = 'signin'", (user,)))
    linker = SessionLinker(signins)
    ev_cache: dict[str, Event] = {}

    def get(eid: str) -> Event | None:
        if eid not in ev_cache:
            e = store.event(eid)
            if e is None:
                return None
            ev_cache[eid] = e
        return ev_cache[eid]

    steps: list[dict[str, Any]] = []
    linked_events: set[str] = set()
    for f in findings:
        evs = [e for e in (get(i) for i in f["event_ids"]) if e is not None]
        linked_events.update(f["event_ids"])
        links = [linker.link(e) for e in evs if e.category != "signin"]
        methods = sorted({lk["method"] for lk in links})
        steps.append({
            "kind": "finding",
            "ts": f["first_ts"],
            "end_ts": f["last_ts"],
            "label": "observed",
            "title": f["summary"],
            "rule_id": f["rule_id"],
            "finding_id": f["id"],
            "level": f["level"],
            "level_reason": f["level_reason"],
            "phase": phase_of.get(f["rule_id"], "other"),
            "event_ids": f["event_ids"],
            "sources": sorted({e.source for e in evs}),
            "session_link": _summarise_links(links),
            "link_methods": methods,
        })
        # an IP/time-based attribution is its own inference step
        inferred = [lk for lk in links if lk["method"] == "ip_time"]
        if inferred:
            steps.append({
                "kind": "attribution",
                "ts": f["first_ts"],
                "end_ts": f["first_ts"],
                "label": "inference",
                "title": f"Attributed to the sign-in from {evs[0].ip.split(':')[0] if evs else ''} by IP address and time, "
                         f"not by a recorded session identifier",
                "basis": [inferred[0]["text"]],
                "finding_id": f["id"],
                "rule_id": f["rule_id"],
                "phase": phase_of.get(f["rule_id"], "other"),
                "event_ids": [i for i in [inferred[0].get("signin_event_id")] if i] + f["event_ids"][:1],
                "sources": [],
            })

    # activity inside flagged sessions that no rule singled out, aggregated per action and hour
    flagged = set(ctx.flagged_sessions) | set(ctx.flagged_tokens)
    if flagged:
        groups: dict[tuple[str, str, str], list[Event]] = defaultdict(list)
        for e in store.query_events("actor = ? AND (session_id != '' OR token_id != '')", (user,)):
            if e.event_id in linked_events or e.link_role in ("duplicate", "corroborating"):
                continue
            if e.category == "signin":
                continue
            if e.session_id in flagged or e.token_id in flagged:
                groups[(e.ts_utc[:13], e.action, e.session_id or e.token_id)].append(e)
        for (_, action, sess), evs in sorted(groups.items()):
            first = evs[0]
            link = linker.link(first)
            steps.append({
                "kind": "session_activity",
                "ts": first.ts_utc,
                "end_ts": evs[-1].ts_utc,
                "label": "observed",
                "title": _describe(action, evs),
                "phase": "other",
                "event_ids": [e.event_id for e in evs[:50]],
                "sources": sorted({e.source for e in evs}),
                "session_link": link,
                "link_methods": [link["method"]],
            })

    steps.extend(_inferences(findings, steps, ctx, window))
    steps.sort(key=lambda s: (s["ts"], 0 if s["label"] == "observed" else 1, s.get("finding_id", ""), s["title"]))
    for i, s in enumerate(steps, 1):
        s["seq"] = i
        s["id"] = f"S{i:03d}-" + short_id(s["ts"], s["title"], length=6)
    return {
        "user": user,
        "steps": steps,
        "linking": _link_stats(store, user, linker),
    }


def _summarise_links(links: list[dict[str, Any]]) -> dict[str, Any]:
    if not links:
        return {"method": "self", "label": "observed", "text": "sign-in records"}
    order = ["token_id", "session_id", "ip_time", "none"]
    best = sorted(links, key=lambda lk: order.index(lk["method"]) if lk["method"] in order else 9)[0]
    out = dict(best)
    if len({lk["method"] for lk in links}) > 1:
        out["text"] += f" (other records in this finding: {', '.join(sorted({lk['method'] for lk in links}))})"
    return out


def _describe(action: str, evs: list[Event]) -> str:
    n = len(evs)
    if action == "mail.send":
        rcpts = sorted({str(e.details.get("recipients", "")) for e in evs if e.details.get("recipients")})
        return f"{n} message(s) sent" + (f" to {', '.join(rcpts)}" if rcpts else "")
    if action.startswith("mail.") and "delete" in action:
        return f"{n} mail deletion record(s) ({evs[0].operation})"
    return f"{n} {evs[0].operation or action} record(s) in the same session"


def _inferences(findings: list[dict[str, Any]], steps: list[dict[str, Any]], ctx: Any,
                window: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    access = [f for f in findings if f["stage"] == "access" and f["level"] in ("confirmed", "probable")]
    if access:
        first = min(access, key=lambda f: f["first_ts"])
        others = [f for f in access if f is not first]
        out.append({
            "kind": "interpretation",
            "ts": first["first_ts"],
            "end_ts": first["first_ts"],
            "label": "inference",
            "title": "Likely start of attacker access to the account",
            "basis": [f"{first['rule_id']} ({first['level']}): {first['summary']}"] +
                     [f"{f['rule_id']} ({f['level']}): {f['summary']}" for f in others[:4]],
            "finding_id": first["id"],
            "phase": "initial_access",
            "event_ids": first["event_ids"][:5],
            "sources": [],
        })
    replay = [f for f in findings if f.get("extra", {}).get("session_replay")]
    for f in replay:
        out.append({
            "kind": "interpretation",
            "ts": f["first_ts"],
            "end_ts": f["last_ts"],
            "label": "inference",
            "title": "The same sign-in session was used from two countries: consistent with a stolen session "
                     "cookie or token (adversary-in-the-middle phishing)",
            "basis": [f"session ID recorded in sign-ins from {', '.join(f['indicators']['ips'])}",
                      f"{f['rule_id']} ({f['level']})"],
            "finding_id": f["id"],
            "phase": "initial_access",
            "event_ids": f["event_ids"][:5],
            "sources": [],
        })
    return out


def _link_stats(store: CaseStore, user: str, linker: SessionLinker) -> dict[str, int]:
    stats: dict[str, int] = defaultdict(int)
    for e in store.query_events("actor = ? AND category != 'signin' AND ts_utc >= ''", (user,)):
        if e.link_role in ("duplicate", "corroborating"):
            continue
        stats[linker.link(e)["method"]] += 1
    return dict(sorted(stats.items()))
