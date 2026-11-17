"""Optional offline IP location database supplied by the analyst.

TenantTrace never looks anything up online and never downloads a database. An analyst who already
has an IP location file can pass it with `--ipdb`; it is used only to fill location fields the logs
leave empty (for example coordinates, which the Entra CSV download does not carry), and every value
taken from it is marked `geo_source = "ipdb:<file>"` so the report can tell it apart from what
Microsoft logged. Values the logs do carry are never overwritten.

Accepted layout: a CSV with a header row and either a `network` column (CIDR, IPv4 or IPv6) or
start/end columns (`start`/`end`, `ip_start`/`ip_end`, `ip_from`/`ip_to`; addresses or integers),
plus any of country, region, city, latitude, longitude under common names.
"""

from __future__ import annotations

import csv
import ipaddress
from bisect import bisect_right
from pathlib import Path
from typing import Any

from tenanttrace.case import ProcessingLog
from tenanttrace.hashing import sha256_file
from tenanttrace.store import CaseStore

ALIASES = {
    "network": ("network", "cidr", "prefix"),
    "start": ("start", "ip_start", "ip_from", "start_ip", "range_start"),
    "end": ("end", "ip_end", "ip_to", "end_ip", "range_end"),
    "country": ("country", "country_code", "country_iso_code", "countrycode", "cc"),
    "region": ("region", "stateprov", "region_name", "subdivision", "state"),
    "city": ("city", "city_name"),
    "lat": ("latitude", "lat"),
    "lon": ("longitude", "lon", "lng"),
}


def _addr(v: str) -> int:
    v = v.strip()
    return int(v) if v.isdigit() else int(ipaddress.ip_address(v))


class IpDb:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.sha256 = sha256_file(self.path)
        self.ranges: dict[int, list[tuple[int, int, dict[str, Any]]]] = {4: [], 6: []}
        with open(self.path, "r", encoding="utf-8-sig", newline="") as fh:
            rd = csv.reader(fh)
            header = [h.strip().lower() for h in next(rd)]
            col = {k: next((header.index(a) for a in names if a in header), None) for k, names in ALIASES.items()}
            if col["network"] is None and (col["start"] is None or col["end"] is None):
                raise ValueError(f"{self.path.name}: no network or start/end columns")
            for row in rd:
                try:
                    if col["network"] is not None:
                        net = ipaddress.ip_network(row[col["network"]].strip(), strict=False)
                        lo, hi, ver = int(net.network_address), int(net.broadcast_address), net.version
                    else:
                        lo, hi = _addr(row[col["start"]]), _addr(row[col["end"]])
                        ver = 6 if ":" in row[col["start"]] or hi > 2**32 else 4
                except (ValueError, IndexError):
                    continue
                info = {}
                for k in ("country", "region", "city", "lat", "lon"):
                    i = col[k]
                    if i is not None and i < len(row) and row[i].strip():
                        info[k] = row[i].strip()
                self.ranges[ver].append((lo, hi, info))
        for v in self.ranges.values():
            v.sort(key=lambda r: r[0])
        self._starts = {v: [r[0] for r in rs] for v, rs in self.ranges.items()}

    def lookup(self, ip: str) -> dict[str, Any] | None:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        rs = self.ranges[a.version]
        i = bisect_right(self._starts[a.version], int(a)) - 1
        if i >= 0 and rs[i][0] <= int(a) <= rs[i][1]:
            return rs[i][2]
        return None


def enrich(store: CaseStore, path: str, log: ProcessingLog) -> dict[str, Any]:
    db = IpDb(Path(path))
    tag = f"ipdb:{db.path.name}"
    updated = 0
    rows = store.conn.execute(
        "SELECT event_id, ip, geo_country, geo_region, geo_city, geo_lat, geo_lon, geo_source FROM events "
        "WHERE ip != '' AND (geo_lat IS NULL OR geo_country = '')"
    ).fetchall()
    for eid, ip, country, region, city, lat, lon, src in rows:
        hit = db.lookup(ip)
        if not hit:
            continue
        new = {
            "geo_country": country or hit.get("country", "").upper(),
            "geo_region": region or hit.get("region", ""),
            "geo_city": city or hit.get("city", ""),
            "geo_lat": lat if lat is not None else (float(hit["lat"]) if "lat" in hit else None),
            "geo_lon": lon if lon is not None else (float(hit["lon"]) if "lon" in hit else None),
        }
        # mark the source as the database only when it supplied something the log lacked
        filled = (not country and new["geo_country"]) or (lat is None and new["geo_lat"] is not None)
        if not filled:
            continue
        store.conn.execute(
            "UPDATE events SET geo_country=?, geo_region=?, geo_city=?, geo_lat=?, geo_lon=?, geo_source=? WHERE event_id=?",
            (new["geo_country"], new["geo_region"], new["geo_city"], new["geo_lat"], new["geo_lon"],
             tag if not src else (src if tag in src else src + "+" + tag), eid))
        updated += 1
    store.commit()
    info = {"file": str(db.path), "sha256": db.sha256, "ranges": sum(len(v) for v in db.ranges.values()),
            "events_enriched": updated}
    log.write("geo", f"offline IP database {db.path.name}: filled location for {updated} event(s)", **info)
    return info
