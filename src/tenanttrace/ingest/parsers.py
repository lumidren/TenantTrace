"""Parsers for each supported export layout, chosen by content, never by file name.

Every parser exposes `sniff` (a score from 0 to 100 and a reason) and `parse`. The runner
calls every parser's `sniff` on a sample of the file and picks the highest score of at least
50; the choice and the reason are written to the manifest and the processing log.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from tenanttrace.hashing import short_id
from tenanttrace.ingest.readers import Encoding, RawRecord, iter_csv, iter_json
from tenanttrace.ingest.signins import (
    CSV_REQUIRED,
    UnrecognisedSignIn,
    interactive_hint_from_name,
    map_csv_header,
    normalize_azure_monitor,
    normalize_csv_signin,
    normalize_graph_signin,
)
from tenanttrace.ingest.ual import UnrecognisedRecord, normalize_auditdata
from tenanttrace.schema import Event

# documented export ceilings (docs/sources/retention-licensing.md section 1, limits table)
UAL_PS_LIMITS = (5000, 10000, 50000)
UAL_PURVIEW_LIMITS = (50000, 1000000)
SIGNIN_DOWNLOAD_LIMIT = 100000
AUDIT_DOWNLOAD_LIMIT = 250000


@dataclass
class Sample:
    rel: str
    shape: str                       # "csv", "json", "empty", "binary"
    header: list[str] = field(default_factory=list)
    preamble: str = ""
    first_obj: Any = None

    @property
    def header_lower(self) -> list[str]:
        return [" ".join(h.strip().lower().split()) for h in self.header]


class ParseState:
    """Collects events and accounting for one input file."""

    def __init__(self, path: Path, rel: str, file_id: int, file_sha: str, enc: Encoding, parser_id: str,
                 sink: Callable[[list[Event]], None], reject_sink: Callable[..., None]):
        self.path = path
        self.rel = rel
        self.file_id = file_id
        self.file_sha = file_sha
        self.enc = enc
        self.parser_id = parser_id
        self._sink = sink
        self._reject = reject_sink
        self.buffer: list[Event] = []
        self.total = 0
        self.parsed = 0
        self.unrecognised = 0
        self.malformed = 0
        self.sources: Counter[str] = Counter()
        self.unmapped: Counter[str] = Counter()
        self.ts_min = ""
        self.ts_max = ""
        self.truncation: list[dict[str, Any]] = []
        self.notes: list[str] = []
        self.ts_notes: Counter[str] = Counter()

    def emit(self, ev: Event, raw: RawRecord, sub: str = "") -> None:
        ev.parser = self.parser_id
        ev.file_id = self.file_id
        ev.line_start, ev.col_start = raw.line_start, raw.col_start
        ev.line_end, ev.col_end = raw.line_end, raw.col_end
        ev.byte_offset = raw.byte_offset
        ev.raw_sha256 = raw.sha256
        if not raw.exact:
            ev.details["raw_exact"] = False
            ev.details["raw_position"] = sub
        ev.event_id = "E" + short_id(self.file_sha, self.rel, str(raw.line_start), str(raw.col_start), sub, length=23)
        self.parsed += 1
        self.sources[ev.source] += 1
        if ev.details.get("unmapped_operation"):
            self.unmapped[ev.operation] += 1
        if ev.ts_note:
            self.ts_notes[ev.ts_note] += 1
        if not self.ts_min or ev.ts_utc < self.ts_min:
            self.ts_min = ev.ts_utc
        if ev.ts_utc > self.ts_max:
            self.ts_max = ev.ts_utc
        self.buffer.append(ev)
        if len(self.buffer) >= 2000:
            self.flush()

    def reject(self, raw: RawRecord, kind: str, reason: str) -> None:
        if kind == "malformed":
            self.malformed += 1
        else:
            self.unrecognised += 1
        self._reject(self.file_id, raw.line_start, raw.line_end, kind, reason, raw.sha256, raw.text[:300])

    def flush(self) -> None:
        if self.buffer:
            self._sink(self.buffer)
            self.buffer = []

    def info(self) -> dict[str, Any]:
        return {
            "sources": sorted(self.sources),
            "events_by_source": dict(sorted(self.sources.items())),
            "first": self.ts_min,
            "last": self.ts_max,
            "truncation": self.truncation,
            "unmapped_operations": dict(self.unmapped.most_common(25)),
            "unmapped_total": sum(self.unmapped.values()),
            "timestamp_interpretation": dict(self.ts_notes.most_common(5)),
            "notes": self.notes,
            "encoding": self.enc.note,
        }


class Parser:
    id = ""
    title = ""
    container = ""

    def sniff(self, s: Sample) -> tuple[int, str]:
        raise NotImplementedError

    def parse(self, st: ParseState) -> None:
        raise NotImplementedError


# ----------------------------------------------------------------------------- UAL


def _wrapper_from_row(header: list[str], row: list[str]) -> dict[str, Any]:
    keep = ("CreationDate", "UserIds", "UserId", "Operations", "Operation", "RecordType", "Identity", "RecordId",
            "ResultIndex", "ResultCount")
    out = {}
    low = {h.strip().lower(): i for i, h in enumerate(header)}
    for k in keep:
        i = low.get(k.lower())
        if i is not None and i < len(row):
            out[k] = row[i]
    return out


class UalCsvParser(Parser):
    container = "ual"

    def __init__(self, pid: str, title: str, want_session_cols: bool, limits: tuple[int, ...]):
        self.id = pid
        self.title = title
        self.want_session_cols = want_session_cols
        self.limits = limits

    def sniff(self, s: Sample) -> tuple[int, str]:
        if s.shape != "csv":
            return 0, "not CSV"
        h = set(s.header_lower)
        if "auditdata" not in h:
            return 0, "no AuditData column"
        session_cols = bool(h & {"resultindex", "resultcount", "runspaceid"})
        if self.want_session_cols != session_cols:
            return 10, "AuditData column present but the wrapper columns belong to another export"
        if self.want_session_cols:
            return 95, "AuditData with Search-UnifiedAuditLog wrapper columns (" + ", ".join(
                c for c in s.header if c.strip().lower() in ("resultindex", "resultcount", "runspaceid")) + ")"
        layout = "8-column (RecordId ... AssociatedAdminUnitsNames)" if "recordid" in h else "4-column"
        return 90, f"AuditData with Purview export columns, {layout} layout"

    def parse(self, st: ParseState) -> None:
        header: list[str] | None = None
        idx = -1
        rows = 0
        max_count = 0
        max_index = 0
        for row in iter_csv(st.path, st.enc):
            if header is None:
                if len(row.fields) == 1 and row.fields[0].startswith("#TYPE"):
                    st.notes.append(f"skipped PowerShell type line: {row.fields[0][:80]}")
                    continue
                header = [h.strip().lstrip("\ufeff") for h in row.fields]
                idx = [h.lower() for h in header].index("auditdata")
                continue
            st.total += 1
            rows += 1
            if len(row.fields) != len(header):
                st.reject(row.raw, "malformed", f"row has {len(row.fields)} fields, header has {len(header)}")
                continue
            wrapper = _wrapper_from_row(header, row.fields)
            try:
                max_count = max(max_count, int(wrapper.get("ResultCount") or 0))
                max_index = max(max_index, int(wrapper.get("ResultIndex") or 0))
            except ValueError:
                pass
            try:
                ad = json.loads(row.fields[idx])
            except json.JSONDecodeError as exc:
                st.reject(row.raw, "malformed", f"AuditData is not valid JSON ({exc.msg})")
                continue
            try:
                ev = normalize_auditdata(ad, wrapper)
            except UnrecognisedRecord as exc:
                st.reject(row.raw, "unrecognised", str(exc))
                continue
            st.emit(ev, row.raw)
        if header is None:
            st.notes.append("no header row")
        if self.want_session_cols and max_count and rows < max_count:
            st.truncation.append({
                "evidence": f"ResultCount reports {max_count:,} results but the file holds {rows:,} rows "
                            f"(highest ResultIndex {max_index:,})",
                "after": st.ts_max,
                "causes": ["the Search-UnifiedAuditLog session stopped paging before all results were retrieved",
                           "a per-session result limit was reached (5,000 / 10,000 / 50,000)",
                           "note: one collector reports that ResultCount may not give the total in recent versions"],
            })
        if rows in self.limits:
            st.truncation.append({
                "evidence": f"the file holds exactly {rows:,} records, a documented export limit",
                "after": st.ts_max,
                "causes": ["the export reached its row limit and silently left records out"],
            })


class UalJsonParser(Parser):
    id = "ual_json"
    title = "Unified audit log records in JSON (wrapper objects or AuditData objects, array or JSON Lines)"
    container = "ual"

    def sniff(self, s: Sample) -> tuple[int, str]:
        o = s.first_obj
        if s.shape != "json":
            return 0, "not JSON"
        if isinstance(o, str):
            try:
                o = json.loads(o)
            except json.JSONDecodeError:
                return 0, "JSON string that is not an AuditData record"
        if not isinstance(o, dict):
            return 0, "first record is not an object"
        if "AuditData" in o and ("Operations" in o or "CreationDate" in o):
            return 95, "JSON wrapper objects with AuditData (Search-UnifiedAuditLog or collector output)"
        if "CreationTime" in o and "Operation" in o and ("RecordType" in o or "Workload" in o):
            return 90, "AuditData objects (Management Activity API shape)"
        return 0, "no AuditData fields"

    def parse(self, st: ParseState) -> None:
        for item in iter_json(st.path, st.enc):
            st.total += 1
            if item.obj is None:
                st.reject(item.raw, "malformed", item.error)
                continue
            obj = item.obj
            wrapper: dict[str, Any] = {}
            if isinstance(obj, str):
                try:
                    obj = json.loads(obj)
                except json.JSONDecodeError:
                    st.reject(item.raw, "unrecognised", "a JSON string that is not an AuditData record")
                    continue
            if isinstance(obj, dict) and "AuditData" in obj:
                wrapper = {k: obj.get(k) for k in ("CreationDate", "UserIds", "Operations", "RecordType", "Identity",
                                                   "ResultIndex", "ResultCount") if k in obj}
                ad = obj["AuditData"]
                if isinstance(ad, str):
                    try:
                        ad = json.loads(ad)
                    except json.JSONDecodeError as exc:
                        st.reject(item.raw, "malformed", f"AuditData is not valid JSON ({exc.msg})")
                        continue
            else:
                ad = obj
            try:
                ev = normalize_auditdata(ad, wrapper)
            except UnrecognisedRecord as exc:
                st.reject(item.raw, "unrecognised", str(exc))
                continue
            if not item.raw.exact:
                st.notes.append(item.note) if len(st.notes) < 3 else None
            st.emit(ev, item.raw, sub=item.note)


# ----------------------------------------------------------------------------- Entra


class EntraCsvParser(Parser):
    id = "entra_signin_csv"
    title = "Microsoft Entra admin-centre sign-in download (CSV)"
    container = "entra_signin"

    def sniff(self, s: Sample) -> tuple[int, str]:
        if s.shape != "csv":
            return 0, "not CSV"
        cols = map_csv_header(s.header)
        missing = [c for c in CSV_REQUIRED if c not in cols]
        if missing:
            return 0, f"missing sign-in columns: {', '.join(missing)}"
        return 90, f"sign-in columns present ({len(cols)} recognised of {len(s.header)})"

    def parse(self, st: ParseState) -> None:
        hint = interactive_hint_from_name(st.rel)
        st.notes.append("interactive/non-interactive taken from the file name" if hint is not None else
                        "no interactive/non-interactive hint in the file name; rows treated as interactive")
        cols: dict[str, int] | None = None
        width = 0
        rows = 0
        for row in iter_csv(st.path, st.enc):
            if cols is None:
                cols = map_csv_header(row.fields)
                width = len(row.fields)
                continue
            st.total += 1
            rows += 1
            if len(row.fields) != width:
                st.reject(row.raw, "malformed", f"row has {len(row.fields)} fields, header has {width}")
                continue
            try:
                ev = normalize_csv_signin(row.fields, cols, hint)
            except UnrecognisedSignIn as exc:
                st.reject(row.raw, "unrecognised", str(exc))
                continue
            st.emit(ev, row.raw)
        if rows == SIGNIN_DOWNLOAD_LIMIT:
            st.truncation.append({"evidence": f"the file holds exactly {rows:,} sign-ins, the documented "
                                              "per-download limit", "after": st.ts_max,
                                  "causes": ["the admin-centre download stopped at its record limit"]})


class EntraJsonParser(Parser):
    id = "entra_signin_json"
    title = "Microsoft Entra sign-ins as Graph signIn objects (JSON download or collector output)"
    container = "entra_signin"

    def sniff(self, s: Sample) -> tuple[int, str]:
        o = s.first_obj
        if s.shape != "json" or not isinstance(o, dict):
            return 0, "not a JSON object stream"
        if "createdDateTime" in o and ("userPrincipalName" in o or "userId" in o) and (
                "ipAddress" in o or "appId" in o or "status" in o):
            return 90, "Graph signIn properties (createdDateTime, userPrincipalName, ipAddress)"
        return 0, "no Graph signIn properties"

    def parse(self, st: ParseState) -> None:
        hint = interactive_hint_from_name(st.rel)
        rows = 0
        for item in iter_json(st.path, st.enc):
            st.total += 1
            rows += 1
            if item.obj is None:
                st.reject(item.raw, "malformed", item.error)
                continue
            try:
                ev = normalize_graph_signin(item.obj, hint)  # type: ignore[arg-type]
            except UnrecognisedSignIn as exc:
                st.reject(item.raw, "unrecognised", str(exc))
                continue
            st.emit(ev, item.raw, sub=item.note)
        if rows == SIGNIN_DOWNLOAD_LIMIT:
            st.truncation.append({"evidence": f"the file holds exactly {rows:,} sign-ins, the documented "
                                              "per-download limit", "after": st.ts_max,
                                  "causes": ["the admin-centre download stopped at its record limit"]})


class AzureMonitorSigninParser(Parser):
    id = "entra_signin_azure_monitor"
    title = "Microsoft Entra sign-ins in the Azure Monitor diagnostic format"
    container = "entra_signin"

    def sniff(self, s: Sample) -> tuple[int, str]:
        o = s.first_obj
        if s.shape != "json" or not isinstance(o, dict):
            return 0, "not a JSON object stream"
        cat = str(o.get("category", "")).lower()
        if isinstance(o.get("properties"), dict) and cat in ("signinlogs", "noninteractiveusersigninlogs"):
            return 95, f"Azure Monitor envelope with category {o.get('category')}"
        return 0, "no Azure Monitor sign-in envelope"

    def parse(self, st: ParseState) -> None:
        for item in iter_json(st.path, st.enc):
            st.total += 1
            if item.obj is None:
                st.reject(item.raw, "malformed", item.error)
                continue
            obj = item.obj
            if not isinstance(obj, dict) or str(obj.get("category", "")).lower() not in (
                    "signinlogs", "noninteractiveusersigninlogs"):
                st.reject(item.raw, "unrecognised", "not a user sign-in record (category "
                                                    f"{obj.get('category') if isinstance(obj, dict) else '?'})")
                continue
            try:
                ev = normalize_azure_monitor(obj)
            except UnrecognisedSignIn as exc:
                st.reject(item.raw, "unrecognised", str(exc))
                continue
            st.emit(ev, item.raw, sub=item.note)


class EntraAuditJsonParser(Parser):
    id = "entra_audit_json"
    title = "Microsoft Entra audit logs as Graph directoryAudit objects"
    container = "entra_audit"

    def sniff(self, s: Sample) -> tuple[int, str]:
        o = s.first_obj
        if s.shape != "json" or not isinstance(o, dict):
            return 0, "not a JSON object stream"
        if "activityDisplayName" in o and "activityDateTime" in o:
            return 90, "Graph directoryAudit properties (activityDisplayName, activityDateTime)"
        return 0, "no directoryAudit properties"

    def parse(self, st: ParseState) -> None:
        from tenanttrace.ingest.entra_audit import normalize_directory_audit

        for item in iter_json(st.path, st.enc):
            st.total += 1
            if item.obj is None:
                st.reject(item.raw, "malformed", item.error)
                continue
            try:
                ev = normalize_directory_audit(item.obj)  # type: ignore[arg-type]
            except ValueError as exc:
                st.reject(item.raw, "unrecognised", str(exc))
                continue
            st.emit(ev, item.raw, sub=item.note)


PARSERS: list[Parser] = [
    UalCsvParser("ps_ual_csv", "Search-UnifiedAuditLog output saved with Export-Csv", True, UAL_PS_LIMITS),
    UalCsvParser("purview_ual_csv", "Microsoft Purview audit search export (CSV)", False, UAL_PURVIEW_LIMITS),
    UalJsonParser(),
    EntraCsvParser(),
    EntraJsonParser(),
    AzureMonitorSigninParser(),
    EntraAuditJsonParser(),
]


def choose(sample: Sample) -> tuple[Parser | None, str, dict[str, Any]]:
    scores = {}
    best: tuple[int, Parser | None, str] = (0, None, "")
    for p in PARSERS:
        score, reason = p.sniff(sample)
        scores[p.id] = {"score": score, "reason": reason}
        if score > best[0]:
            best = (score, p, reason)
    if best[1] is None or best[0] < 50:
        return None, "no parser recognised this file", scores
    return best[1], best[2], scores
