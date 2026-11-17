"""Rule engine: loads YAML rules and evaluates them against one account's events.

Rule kinds:
  match      every event that satisfies `select` is a finding (optionally grouped)
  threshold  `count` or more selected events inside a sliding `within` window, optionally
             grouped by fields and compared with the account's own baseline rate
  deviation  selected events in the compromise window whose `attribute` value never occurs
             in the account's baseline
  sequence   a `first` pattern followed by a `then` pattern within a time limit, joined on
             shared fields
  travel     consecutive successful sign-ins whose implied speed is physically implausible

Rules run in two stages. `access` rules (sign-in behaviour) run first; the IPs, sessions,
tokens and user agents of their findings at probable level or above become context for the
`post` rules (mailbox, file, consent activity), which is how a hiding inbox rule created in an
attacker's session can be confirmed rather than merely possible.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from importlib import resources
from typing import Any, Callable, Iterable

import yaml

from tenanttrace.hashing import short_id
from tenanttrace.ingest.timeparse import parse_utc
from tenanttrace.rules.baseline import Baseline, ua_family
from tenanttrace.rules.conditions import _MISSING, eval_event, eval_group, get_field
from tenanttrace.schema import Event

LEVELS = ("confirmed", "probable", "possible")
LEVEL_RANK = {"confirmed": 3, "probable": 2, "possible": 1}
MAX_EVIDENCE = 200


def parse_duration(s: Any) -> timedelta:
    if isinstance(s, (int, float)):
        return timedelta(minutes=float(s))
    s = str(s).strip()
    unit = s[-1]
    v = float(s[:-1])
    return {"s": timedelta(seconds=v), "m": timedelta(minutes=v), "h": timedelta(hours=v),
            "d": timedelta(days=v)}[unit]


@dataclass
class Rule:
    data: dict[str, Any]

    @property
    def id(self) -> str:
        return self.data["id"]

    @property
    def kind(self) -> str:
        return self.data["kind"]

    @property
    def stage(self) -> str:
        return self.data.get("stage", "post")

    @property
    def title(self) -> str:
        return self.data["title"]

    def sources_spec(self) -> dict[str, list[str]]:
        s = self.data.get("sources", {})
        if isinstance(s, list):
            return {"any": s}
        return s


REQUIRED_KEYS = ("id", "title", "kind", "sources", "why", "benign", "confidence", "attack", "version")


def load_rules() -> tuple[str, list[Rule]]:
    pkg = resources.files("tenanttrace.rules")
    meta = yaml.safe_load(pkg.joinpath("ruleset.yaml").read_text(encoding="utf-8"))
    rules = []
    for name in sorted(p.name for p in pkg.iterdir() if p.name.startswith("TT-") and p.name.endswith(".yaml")):
        data = yaml.safe_load(pkg.joinpath(name).read_text(encoding="utf-8"))
        missing = [k for k in REQUIRED_KEYS if k not in data]
        if missing:
            raise ValueError(f"rule {name} is missing {missing}")
        levels = [c["level"] for c in data["confidence"]]
        if any(lv not in LEVELS for lv in levels):
            raise ValueError(f"rule {name} uses an unknown confidence level")
        rules.append(Rule(data))
    return str(meta.get("version")), rules


# ----------------------------------------------------------------------------- context


@dataclass
class Context:
    user: str
    window_start: str
    baseline: Baseline
    tenant_domains: set[str]
    session_countries: dict[str, set[str]]
    ip_failed_users: dict[str, set[str]]
    flagged_ips: set[str] = field(default_factory=set)
    suspect_ips: set[str] = field(default_factory=set)
    flagged_sessions: set[str] = field(default_factory=set)
    flagged_tokens: set[str] = field(default_factory=set)
    flagged_uas: set[str] = field(default_factory=set)
    flagged_apps: set[str] = field(default_factory=set)

    def check(self, name: str, ev: Event) -> bool:
        b = self.baseline
        if name == "ip_in_baseline":
            return bool(ev.ip) and ev.ip in b.ips
        if name == "country_in_baseline":
            return bool(ev.geo_country) and ev.geo_country.upper() in b.countries
        if name == "device_in_baseline":
            if ev.device_id and ev.device_id.lower() in b.device_ids:
                return True
            pair = f"{ev.device_os}|{ev.device_browser}".lower()
            fam = ua_family(ev.user_agent)
            return (pair != "|" and pair in b.device_pairs and (not fam or fam in b.ua_families)) or (
                not ev.device_os and bool(fam) and fam in b.ua_families)
        if name == "ua_in_baseline":
            fam = ua_family(ev.user_agent)
            return bool(fam) and fam in b.ua_families
        if name == "known_context":
            return self.check("ip_in_baseline", ev) and self.check("device_in_baseline", ev)
        if name == "session_flagged":
            return bool(ev.session_id) and ev.session_id in self.flagged_sessions
        if name == "token_flagged":
            return bool(ev.token_id) and ev.token_id in self.flagged_tokens
        if name == "session_or_token_flagged":
            return self.check("session_flagged", ev) or self.check("token_flagged", ev)
        if name == "ip_flagged":
            return bool(ev.ip) and ev.ip in self.flagged_ips
        if name == "ip_suspect":
            return bool(ev.ip) and ev.ip in self.suspect_ips
        if name == "session_replayed":
            return bool(ev.session_id) and len(self.session_countries.get(ev.session_id, ())) >= 2
        if name == "external_target":
            tgt = str(ev.details.get("forward_to") or ev.details.get("share_target") or ev.target or "")
            doms = _domains(tgt)
            return bool(doms) and any(d not in self.tenant_domains for d in doms)
        if name == "app_flagged":
            return bool(ev.app_id) and ev.app_id.lower() in self.flagged_apps
        if name == "has_session_id":
            return bool(ev.session_id or ev.token_id)
        if name == "ip_failed_many_users":
            return bool(ev.ip) and len(self.ip_failed_users.get(ev.ip, ())) >= 3
        if name == "in_window":
            return ev.ts_utc >= self.window_start
        raise ValueError(f"unknown context predicate {name!r}")


def _domains(text: str) -> list[str]:
    out = []
    for part in text.replace(";", ",").split(","):
        part = part.strip().lower()
        if part.startswith("smtp:"):
            part = part[5:]
        if "@" in part:
            out.append(part.rsplit("@", 1)[1].strip(" >\"'"))
    return out


# ----------------------------------------------------------------------------- findings


@dataclass
class Finding:
    rule: Rule
    events: list[Event]
    extra: dict[str, Any] = field(default_factory=dict)
    level: str = ""
    reason: str = ""
    baseline_ips: frozenset[str] = frozenset()

    @property
    def first_ts(self) -> str:
        return min(e.ts_utc for e in self.events)

    @property
    def last_ts(self) -> str:
        return max(e.ts_utc for e in self.events)

    def finding_id(self) -> str:
        ids = sorted(e.event_id for e in self.events)
        return f"F-{short_id(self.rule.id, *ids, length=10)}"

    def suspect_events(self) -> list[Event]:
        """The triggering events that do not come from the account's own baseline IP addresses.

        An impossible-travel pair, for example, contains the user's genuine sign-in as well as the
        suspicious one; only the latter may contribute attacker indicators.
        """
        out = [e for e in self.events if not e.ip or e.ip not in self.baseline_ips]
        return out or list(self.events)

    def indicators(self) -> dict[str, list[str]]:
        evs = self.suspect_events()

        def vals(attr: str) -> list[str]:
            return sorted({getattr(e, attr) for e in evs if getattr(e, attr)})
        return {
            "ips": vals("ip"),
            "session_ids": vals("session_id"),
            "token_ids": vals("token_id"),
            "user_agents": vals("user_agent"),
            "app_ids": sorted({e.app_id.lower() for e in evs if e.app_id}),
        }

    def to_json(self) -> dict[str, Any]:
        r = self.rule.data
        ev_sorted = sorted(self.events, key=lambda e: (e.ts_utc, e.event_id))
        return {
            "id": self.finding_id(),
            "rule_id": r["id"],
            "rule_version": r["version"],
            "title": r["title"],
            "stage": self.rule.stage,
            "level": self.level,
            "level_reason": self.reason,
            "summary": render(r.get("summary", r["title"]), ev_sorted[0], self.extra, len(self.events)),
            "first_ts": self.first_ts,
            "suspect_first_ts": min(e.ts_utc for e in self.suspect_events()),
            "suspect_event_ids": sorted(e.event_id for e in self.suspect_events())[:MAX_EVIDENCE],
            "last_ts": self.last_ts,
            "event_count": len(self.events),
            "event_ids": [e.event_id for e in ev_sorted[:MAX_EVIDENCE]],
            "evidence_truncated": len(self.events) > MAX_EVIDENCE,
            "actors": sorted({e.actor for e in self.events if e.actor}),
            "indicators": self.indicators(),
            "attack": r["attack"],
            "why": r["why"].strip(),
            "benign": r["benign"],
            "category": r.get("category", ""),
            "pivot_app": bool(r.get("pivot_app")),
            "extra": self.extra,
        }


def _render_plain(template: str, ev: Event, extra: dict[str, Any], n: int) -> tuple[str, bool]:
    """Fill {placeholders}; return the text and whether every placeholder had a value."""
    out = []
    complete = True
    i = 0
    while i < len(template):
        j = template.find("{", i)
        if j < 0:
            out.append(template[i:])
            break
        k = template.find("}", j)
        out.append(template[i:j])
        key = template[j + 1:k]
        if key == "count":
            val: Any = n
        elif key.startswith("extra."):
            val = extra.get(key[6:], "")
        else:
            val = get_field(ev, key)
            if val is _MISSING:
                val = ""
        if isinstance(val, list):
            val = ", ".join(str(x) for x in val)
        if val in (None, "", False):
            complete = False if val is not False else complete
        if val is True:
            val = "yes"
        elif val is False:
            val = "no"
        out.append(str(val) if val not in (None, "") else "(not recorded)")
        i = k + 1
    return "".join(out), complete


def render(template: str, ev: Event, extra: dict[str, Any], n: int) -> str:
    """Fill a summary template. A segment written as [[ ... ]] is left out entirely when any
    placeholder inside it has no value, so summaries never print "(not recorded)" for optional parts."""
    out = []
    i = 0
    while True:
        j = template.find("[[", i)
        if j < 0:
            out.append(_render_plain(template[i:], ev, extra, n)[0])
            break
        k = template.find("]]", j)
        out.append(_render_plain(template[i:j], ev, extra, n)[0])
        seg, complete = _render_plain(template[j + 2:k], ev, extra, n)
        if complete:
            out.append(seg)
        i = k + 2
    return "".join(out)


# ----------------------------------------------------------------------------- evaluation


class Engine:
    def __init__(self, rules: list[Rule], ctx: Context, all_events: list[Event],
                 tenant_events: Callable[[], Iterable[Event]] | None = None):
        self.rules = rules
        self.ctx = ctx
        self.events = [e for e in all_events if e.link_role not in ("duplicate", "corroborating")]
        self.tenant_events = tenant_events

    def select(self, cond: Any, events: Iterable[Event]) -> list[Event]:
        return [e for e in events if eval_event(cond, e, self.ctx.check)]

    def run_rule(self, rule: Rule) -> list[Finding]:
        d = rule.data
        kind = rule.kind
        pool = self.events
        if d.get("window_only"):
            pool = [e for e in pool if e.ts_utc >= self.ctx.window_start]
        if kind == "match":
            hits = self.select(d["select"], pool)
            findings = self._group(rule, hits)
        elif kind == "threshold":
            findings = self._threshold(rule, self.select(d["select"], pool))
        elif kind == "deviation":
            findings = self._deviation(rule, self.select(d["select"], pool))
        elif kind == "sequence":
            findings = self._sequence(rule, pool)
        elif kind == "travel":
            findings = self._travel(rule, self.select(d["select"], self.events))
        else:
            raise ValueError(f"unknown rule kind {kind}")
        for f in findings:
            f.baseline_ips = frozenset(self.ctx.baseline.ips)
            self._grade(f)
        return findings

    # -- grouping ----------------------------------------------------------
    def _group(self, rule: Rule, hits: list[Event]) -> list[Finding]:
        g = rule.data.get("group")
        if not g:
            return [Finding(rule, [e]) for e in hits]
        by = g.get("by", [])
        within = parse_duration(g.get("within", "1h"))
        buckets: dict[tuple, list[list[Event]]] = defaultdict(list)
        for e in sorted(hits, key=lambda x: x.ts_utc):
            key = tuple(str(get_field(e, f)) for f in by)
            runs = buckets[key]
            if runs and parse_utc(e.ts_utc) - parse_utc(runs[-1][-1].ts_utc) <= within:
                runs[-1].append(e)
            else:
                runs.append([e])
        out = []
        for runs in buckets.values():
            for run in runs:
                out.append(Finding(rule, run))
        return out

    def _threshold(self, rule: Rule, hits: list[Event]) -> list[Finding]:
        t = rule.data["threshold"]
        within = parse_duration(t["within"])
        min_count = int(t["count"])
        by = t.get("group_by", [])
        factor = float(t.get("baseline_factor", 0))
        groups: dict[tuple, list[Event]] = defaultdict(list)
        for e in hits:
            groups[tuple(str(get_field(e, f)) for f in by)].append(e)
        # baseline peak: most selected events inside any `within` window before the compromise window
        base_peak = 0
        if factor:
            base_events = sorted((e for e in hits if e.ts_utc < self.ctx.window_start), key=lambda x: x.ts_utc)
            base_peak = _max_in_window(base_events, within)
        need = max(min_count, math.floor(factor * base_peak) + 1 if factor else 0)
        out = []
        for key, evs in groups.items():
            evs.sort(key=lambda x: x.ts_utc)
            for cluster in _clusters(evs, within, need):
                f = Finding(rule, cluster, extra={"threshold": need, "baseline_peak": base_peak,
                                                   "window": t["within"]})
                out.append(f)
        return out

    def _deviation(self, rule: Rule, hits: list[Event]) -> list[Finding]:
        dv = rule.data["deviation"]
        attr = dv["attribute"]
        b = self.ctx.baseline
        known = {
            "country": b.countries,
            "ip": b.ips,
            "ua_family": b.ua_families,
            "client_app": b.client_apps,
            "device": None,
        }[attr]
        groups: dict[str, list[Event]] = defaultdict(list)
        for e in hits:
            if e.ts_utc < self.ctx.window_start:
                continue
            if attr == "country":
                v = e.geo_country.upper()
            elif attr == "ip":
                v = e.ip
            elif attr == "ua_family":
                v = ua_family(e.user_agent)
            elif attr == "client_app":
                v = e.client_app.lower()
            else:  # device
                if self.ctx.check("device_in_baseline", e):
                    continue
                v = e.device_id.lower() or f"{e.device_os}|{e.device_browser}|{ua_family(e.user_agent)}".lower()
            if not v:
                continue
            if known is not None and v in known:
                continue
            groups[v].append(e)
        return [Finding(rule, evs, extra={"new_value": v, "attribute": attr}) for v, evs in sorted(groups.items())]

    def _sequence(self, rule: Rule, pool: list[Event]) -> list[Finding]:
        sq = rule.data["sequence"]
        within = parse_duration(sq.get("within", "7d"))
        first_src = self.events
        if sq.get("first_scope") == "tenant" and self.tenant_events is not None:
            first_src = list(self.tenant_events())
        firsts = self.select(sq["first"], first_src)
        thens = self.select(sq["then"], pool)
        join = sq.get("join", [])
        first_min = int(sq.get("first_min_count", 1))
        out = []
        # group the `first` events by join key
        by_key: dict[tuple, list[Event]] = defaultdict(list)
        for e in firsts:
            by_key[tuple(_join_val(e, j, "first") for j in join)].append(e)
        for key, fevs in sorted(by_key.items()):
            if any(k == "" for k in key):
                continue
            fevs.sort(key=lambda x: x.ts_utc)
            if len(fevs) < first_min:
                continue
            start = parse_utc(fevs[0].ts_utc)
            matched = [t for t in thens
                       if tuple(_join_val(t, j, "then") for j in join) == key
                       and start <= parse_utc(t.ts_utc) <= parse_utc(fevs[-1].ts_utc) + within]
            if matched:
                cap = int(sq.get("first_evidence_cap", 25))
                out.append(Finding(rule, fevs[:cap] + matched,
                                   extra={"first_count": len(fevs), "then_count": len(matched)}))
        return out

    def _travel(self, rule: Rule, signins: list[Event]) -> list[Finding]:
        tv = rule.data["travel"]
        max_kmh = float(tv.get("max_kmh", 900))
        min_km = float(tv.get("min_km", 500))
        pts = [e for e in signins if e.geo_lat is not None and e.geo_lon is not None and e.outcome == "success"]
        pts.sort(key=lambda x: (x.ts_utc, x.event_id))
        out = []
        seen: set[tuple[str, str]] = set()
        for a, b in zip(pts, pts[1:]):
            if b.ts_utc < self.ctx.window_start and a.ts_utc < self.ctx.window_start:
                continue
            km = haversine(a.geo_lat, a.geo_lon, b.geo_lat, b.geo_lon)
            if km < min_km:
                continue
            hours = max((parse_utc(b.ts_utc) - parse_utc(a.ts_utc)).total_seconds() / 3600.0, 1 / 60)
            kmh = km / hours
            if kmh <= max_kmh:
                continue
            key = (a.geo_country + a.geo_city, b.geo_country + b.geo_city)
            if key in seen:
                continue
            seen.add(key)
            out.append(Finding(rule, [a, b], extra={
                "distance_km": round(km), "hours": round(hours, 2), "speed_kmh": round(kmh),
                "from": f"{a.geo_city}, {a.geo_country}", "to": f"{b.geo_city}, {b.geo_country}"}))
        return out

    # -- confidence --------------------------------------------------------
    def _grade(self, f: Finding) -> None:
        for c in f.rule.data["confidence"]:
            if eval_group(c.get("when", True), f.events, self.ctx.check):
                f.level = c["level"]
                f.reason = render(c["reason"], f.events[0], f.extra, len(f.events))
                return
        f.level = "possible"
        f.reason = "no confidence criterion matched; defaulted to the lowest level"


def _join_val(e: Event, j: Any, side: str) -> str:
    if isinstance(j, dict):
        path = j[side]
    else:
        path = j
    v = get_field(e, path)
    return "" if v is _MISSING or v is None else str(v).lower()


def _max_in_window(evs: list[Event], within: timedelta) -> int:
    best = 0
    j = 0
    times = [parse_utc(e.ts_utc) for e in evs]
    for i in range(len(times)):
        while times[i] - times[j] > within:
            j += 1
        best = max(best, i - j + 1)
    return best


def _clusters(evs: list[Event], within: timedelta, need: int) -> list[list[Event]]:
    """Maximal runs where every event is within `within` of the run's previous event and the run
    reaches `need` events inside some window of length `within`."""
    out: list[list[Event]] = []
    if not evs:
        return out
    times = [parse_utc(e.ts_utc) for e in evs]
    run = [0]
    for i in range(1, len(evs)):
        if times[i] - times[run[-1]] <= within:
            run.append(i)
        else:
            if _max_in_window([evs[k] for k in run], within) >= need:
                out.append([evs[k] for k in run])
            run = [i]
    if _max_in_window([evs[k] for k in run], within) >= need:
        out.append([evs[k] for k in run])
    return out


def haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = p2 - p1
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))
