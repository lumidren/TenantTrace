"""Cross-log linking of records that describe the same action.

Two kinds of link are made after all inputs are parsed:

  duplicate      the same record appears more than once (overlapping exports, repeated pages):
                 same source family and native record ID, same time and outcome. The first
                 copy (by file order) stays primary; the others are kept but excluded from
                 counts and detection.
  corroborating  the unified audit log's copy of an Entra sign-in (UserLoggedIn /
                 UserLoginFailed) matched to the Entra sign-in log record: same account, same
                 IP address, same outcome, within a few seconds. The Entra record stays primary
                 because it carries location, device and MFA detail.

Nothing is deleted; every link records its basis so the report can show why two records were
treated as one action.
"""

from __future__ import annotations

from bisect import bisect_left
from collections import defaultdict
from typing import Any

from tenanttrace.case import ProcessingLog
from tenanttrace.ingest.timeparse import parse_utc
from tenanttrace.store import CaseStore

CORROBORATE_SECONDS = 5.0
SIGNIN_SOURCES = ("entra_signin_interactive", "entra_signin_noninteractive")


def _family(source: str) -> str:
    return "ual" if source.startswith("ual_") else source


def link_events(store: CaseStore, log: ProcessingLog) -> dict[str, Any]:
    conn = store.conn
    conn.execute("UPDATE events SET link_group='', link_role='', link_basis=''")
    dup = 0
    groups: dict[tuple[str, str], list[tuple[str, str, str, int, int]]] = defaultdict(list)
    for eid, source, rid, ts, outcome, fid, line in conn.execute(
            "SELECT event_id, source, record_id, ts_utc, outcome, file_id, line_start FROM events "
            "WHERE record_id != '' ORDER BY file_id, line_start, col_start"):
        groups[(_family(source), rid)].append((eid, ts, outcome, fid, line))
    updates = []
    for (fam, rid), rows in groups.items():
        if len(rows) < 2:
            continue
        primary = rows[0]
        had_dup = False
        for r in rows[1:]:
            if r[1] == primary[1] and r[2] == primary[2]:
                updates.append(("dup:" + primary[0], "duplicate",
                                f"same {fam} record ID {rid} and time as {primary[0]} (file {primary[3]} line {primary[4]})",
                                r[0]))
                dup += 1
                had_dup = True
        if had_dup:
            updates.append(("dup:" + primary[0], "primary", "first copy of a repeated record", primary[0]))
    conn.executemany("UPDATE events SET link_group=?, link_role=?, link_basis=? WHERE event_id=?", updates)

    # corroboration: UAL sign-in copies -> Entra sign-in records
    index: dict[tuple[str, str, str], list[tuple[str, str]]] = defaultdict(list)
    for eid, actor, ip, outcome, ts in conn.execute(
            "SELECT event_id, actor, ip, outcome, ts_utc FROM events WHERE source IN (?, ?) "
            "AND (link_role = '' OR link_role = 'primary') ORDER BY ts_utc",
            SIGNIN_SOURCES):
        index[(actor, ip, outcome)].append((ts, eid))
    corr_updates = []
    primaries: dict[str, str] = {}
    corr = 0
    for eid, actor, ip, outcome, ts, app in conn.execute(
            "SELECT event_id, actor, ip, outcome, ts_utc, app_id FROM events WHERE source = 'ual_azuread_logon' "
            "AND link_role = ''"):
        cands = index.get((actor, ip, outcome))
        if not cands:
            continue
        keys = [c[0] for c in cands]
        i = bisect_left(keys, ts)
        best = None
        t = parse_utc(ts)
        for j in (i - 1, i, i + 1):
            if 0 <= j < len(cands):
                dt = abs((parse_utc(cands[j][0]) - t).total_seconds())
                if dt <= CORROBORATE_SECONDS and (best is None or dt < best[0]):
                    best = (dt, cands[j][1])
        if best is None:
            continue
        corr += 1
        corr_updates.append((f"sig:{best[1]}", "corroborating",
                             f"UAL copy of Entra sign-in {best[1]}: same account, IP address and outcome, "
                             f"{best[0]:.1f} s apart", eid))
        primaries[best[1]] = f"sig:{best[1]}"
    conn.executemany("UPDATE events SET link_group=?, link_role=?, link_basis=? WHERE event_id=?", corr_updates)
    conn.executemany(
        "UPDATE events SET link_group=?, link_role='primary', link_basis='Entra sign-in record with a UAL copy' "
        "WHERE event_id=? AND link_role = ''", [(g, e) for e, g in primaries.items()])
    store.commit()
    summary = {"duplicates": dup, "corroborating": corr}
    log.write("link", f"{dup} duplicate record(s) and {corr} UAL sign-in cop(ies) linked to Entra sign-ins",
              **summary)
    return summary
