"""The account's own history before the suspected compromise window.

"Unusual" in TenantTrace always means "not seen for this account in the supplied logs before
the suspected compromise window". The baseline records which IP addresses, countries,
devices, user agents and client apps the account used, how much file activity it had per
day, and how much history each source actually provides, so rules can refuse to judge
"unusual" when the history is too short.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable

from tenanttrace.ingest.timeparse import parse_utc
from tenanttrace.schema import Event


# Sign-in history (countries, devices, how far back it reaches) comes from the Entra sign-in logs only:
# the unified audit log's copies of sign-ins carry no location or device detail.
SIGNIN_LOG_SOURCES = ("entra_signin_interactive", "entra_signin_noninteractive")


def ua_family(ua: str) -> str:
    """Coarse user-agent family: product tokens without version numbers."""
    if not ua:
        return ""
    u = ua.lower()
    for key in ("edg/", "chrome/", "firefox/", "safari/", "outlook-ios", "outlook-android",
                "microsoft office", "python-requests", "curl/", "okhttp", "imap", "go-http-client",
                "powershell", "axios", "node-fetch"):
        if key in u:
            os_part = ""
            for os_key in ("windows", "mac os", "linux", "android", "iphone", "ipad"):
                if os_key in u:
                    os_part = os_key
                    break
            return f"{key.rstrip('/')}|{os_part}"
    return u[:40]


@dataclass
class Baseline:
    start: str = ""
    end: str = ""                      # window start (exclusive)
    events: int = 0
    days_covered: int = 0
    signin_events: int = 0
    signin_days: int = 0
    signin_start: str = ""
    ips: set[str] = field(default_factory=set)
    countries: set[str] = field(default_factory=set)
    device_ids: set[str] = field(default_factory=set)
    device_pairs: set[str] = field(default_factory=set)   # os|browser
    ua_families: set[str] = field(default_factory=set)
    client_apps: set[str] = field(default_factory=set)
    app_ids: set[str] = field(default_factory=set)
    daily_file_downloads: dict[str, int] = field(default_factory=dict)
    sources: dict[str, dict[str, Any]] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        dl = list(self.daily_file_downloads.values())
        return {
            "start": self.start,
            "end": self.end,
            "events": self.events,
            "days_covered": self.days_covered,
            "signin_events": self.signin_events,
            "signin_days": self.signin_days,
            "signin_start": self.signin_start,
            "distinct_ips": len(self.ips),
            "countries": sorted(self.countries),
            "distinct_devices": len(self.device_ids | self.device_pairs),
            "ua_families": sorted(self.ua_families),
            "client_apps": sorted(self.client_apps),
            "max_daily_file_downloads": max(dl) if dl else 0,
            "sources": self.sources,
        }


def build_baseline(events: Iterable[Event], window_start: str) -> Baseline:
    b = Baseline(end=window_start)
    days: set[str] = set()
    signin_days: set[str] = set()
    per_source: dict[str, dict[str, Any]] = defaultdict(lambda: {"events": 0, "first": "", "last": "", "days": set()})
    downloads: dict[str, int] = defaultdict(int)
    for ev in events:
        if ev.ts_utc >= window_start:
            continue
        if ev.link_role in ("duplicate", "corroborating"):
            continue
        b.events += 1
        day = ev.ts_utc[:10]
        days.add(day)
        if not b.start or ev.ts_utc < b.start:
            b.start = ev.ts_utc
        s = per_source[ev.source]
        s["events"] += 1
        s["first"] = s["first"] or ev.ts_utc
        s["last"] = ev.ts_utc
        s["days"].add(day)
        if ev.ip:
            b.ips.add(ev.ip)
        if ev.category == "signin" and ev.source in SIGNIN_LOG_SOURCES:
            if ev.outcome != "success":
                continue
            b.signin_events += 1
            signin_days.add(day)
            if not b.signin_start or ev.ts_utc < b.signin_start:
                b.signin_start = ev.ts_utc
            if ev.geo_country:
                b.countries.add(ev.geo_country.upper())
            if ev.client_app:
                b.client_apps.add(ev.client_app.lower())
        if ev.app_id:
            b.app_ids.add(ev.app_id.lower())
        if ev.device_id:
            b.device_ids.add(ev.device_id.lower())
        if ev.device_os or ev.device_browser:
            b.device_pairs.add(f"{ev.device_os}|{ev.device_browser}".lower())
        fam = ua_family(ev.user_agent)
        if fam:
            b.ua_families.add(fam)
        if ev.action in ("file.downloaded", "file.sync_downloaded"):
            downloads[day] += 1
    b.days_covered = len(days)
    b.signin_days = len(signin_days)
    b.daily_file_downloads = dict(downloads)
    b.sources = {k: {"events": v["events"], "first": v["first"], "last": v["last"], "days": len(v["days"])}
                 for k, v in sorted(per_source.items())}
    return b


def span_days(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return (parse_utc(b) - parse_utc(a)).total_seconds() / 86400.0


def iso_to_dt(s: str) -> datetime:
    return parse_utc(s)
