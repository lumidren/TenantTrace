"""One SQLite database per case, using only the standard library."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable, Iterator

from tenanttrace.schema import EVENT_COLUMNS, SCHEMA_VERSION, Event

_REAL = {"geo_lat", "geo_lon"}
_INT = {"file_id", "line_start", "col_start", "line_end", "col_end", "byte_offset", "interactive"}


def _coltype(name: str) -> str:
    if name in _REAL:
        return "REAL"
    if name in _INT:
        return "INTEGER"
    return "TEXT"


_EVENT_DDL = ",\n  ".join(
    f"{c} {_coltype(c)}{' PRIMARY KEY' if c == 'event_id' else ''}" for c in EVENT_COLUMNS
)

DDL = f"""
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS files (
  file_id INTEGER PRIMARY KEY,
  rel_path TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size INTEGER NOT NULL,
  parser TEXT,
  parser_reason TEXT,
  encoding TEXT,
  records_total INTEGER DEFAULT 0,
  records_parsed INTEGER DEFAULT 0,
  records_unrecognised INTEGER DEFAULT 0,
  records_malformed INTEGER DEFAULT 0,
  info TEXT
);
CREATE TABLE IF NOT EXISTS events (
  {_EVENT_DDL}
);
CREATE TABLE IF NOT EXISTS unrecognised (
  file_id INTEGER,
  line_start INTEGER,
  line_end INTEGER,
  kind TEXT,
  reason TEXT,
  raw_sha256 TEXT,
  excerpt TEXT
);
CREATE TABLE IF NOT EXISTS analysis (key TEXT PRIMARY KEY, json TEXT);
"""

INDEXES = """
CREATE INDEX IF NOT EXISTS ix_events_actor_ts ON events(actor, ts_utc);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts_utc);
CREATE INDEX IF NOT EXISTS ix_events_ip ON events(ip);
CREATE INDEX IF NOT EXISTS ix_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS ix_events_token ON events(token_id);
CREATE INDEX IF NOT EXISTS ix_events_app ON events(app_id);
CREATE INDEX IF NOT EXISTS ix_events_source ON events(source);
CREATE INDEX IF NOT EXISTS ix_events_record ON events(record_id);
"""


class CaseStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(DDL)
        self.set_meta("schema_version", SCHEMA_VERSION)
        self.conn.commit()

    # -- lifecycle -------------------------------------------------------
    def close(self) -> None:
        self.conn.commit()
        self.conn.close()

    def __enter__(self) -> "CaseStore":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def bulk_mode(self) -> None:
        """Faster inserts during ingest. The database is derived data and can be rebuilt."""
        self.conn.execute("PRAGMA journal_mode=OFF")
        self.conn.execute("PRAGMA synchronous=OFF")

    def build_indexes(self) -> None:
        self.conn.executescript(INDEXES)
        self.conn.commit()

    # -- meta / analysis blobs ------------------------------------------
    def set_meta(self, key: str, value: str) -> None:
        self.conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", (key, value))

    def get_meta(self, key: str, default: str | None = None) -> str | None:
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else default

    def put_analysis(self, key: str, obj: Any) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO analysis(key, json) VALUES (?, ?)",
            (key, json.dumps(obj, sort_keys=True, ensure_ascii=False)),
        )
        self.conn.commit()

    def get_analysis(self, key: str) -> Any:
        row = self.conn.execute("SELECT json FROM analysis WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    # -- files -----------------------------------------------------------
    def add_file(self, rel_path: str, sha256: str, size: int) -> int:
        cur = self.conn.execute(
            "INSERT INTO files(rel_path, sha256, size) VALUES (?, ?, ?)", (rel_path, sha256, size)
        )
        return int(cur.lastrowid)

    def update_file(self, file_id: int, **values: Any) -> None:
        if "info" in values and not isinstance(values["info"], str):
            values["info"] = json.dumps(values["info"], sort_keys=True)
        cols = ", ".join(f"{k}=?" for k in values)
        self.conn.execute(f"UPDATE files SET {cols} WHERE file_id=?", (*values.values(), file_id))

    def files(self) -> list[dict[str, Any]]:
        out = []
        for r in self.conn.execute("SELECT * FROM files ORDER BY file_id"):
            d = dict(r)
            d["info"] = json.loads(d["info"]) if d.get("info") else {}
            out.append(d)
        return out

    def file(self, file_id: int) -> dict[str, Any] | None:
        for f in self.files():
            if f["file_id"] == file_id:
                return f
        return None

    # -- events ----------------------------------------------------------
    def insert_events(self, events: Iterable[Event]) -> int:
        cols = ", ".join(EVENT_COLUMNS)
        qs = ", ".join("?" for _ in EVENT_COLUMNS)
        sql = f"INSERT INTO events({cols}) VALUES ({qs})"  # a collision must fail loudly, never drop a record
        rows = []
        n = 0
        for ev in events:
            row = ev.to_row()
            rows.append(tuple(row[c] for c in EVENT_COLUMNS))
            if len(rows) >= 5000:
                self.conn.executemany(sql, rows)
                n += len(rows)
                rows.clear()
        if rows:
            self.conn.executemany(sql, rows)
            n += len(rows)
        return n

    def add_unrecognised(
        self, file_id: int, line_start: int, line_end: int, kind: str, reason: str, raw_sha256: str, excerpt: str
    ) -> None:
        self.conn.execute(
            "INSERT INTO unrecognised VALUES (?, ?, ?, ?, ?, ?, ?)",
            (file_id, line_start, line_end, kind, reason, raw_sha256, excerpt[:300]),
        )

    def query_events(self, where: str = "1=1", params: tuple = (), order: str = "ts_utc, event_id") -> Iterator[Event]:
        sql = f"SELECT * FROM events WHERE {where} ORDER BY {order}"
        for r in self.conn.execute(sql, params):
            yield Event.from_row(dict(r))

    def event(self, event_id: str) -> Event | None:
        r = self.conn.execute("SELECT * FROM events WHERE event_id=?", (event_id,)).fetchone()
        return Event.from_row(dict(r)) if r else None

    def count(self, where: str = "1=1", params: tuple = ()) -> int:
        return int(self.conn.execute(f"SELECT COUNT(*) FROM events WHERE {where}", params).fetchone()[0])

    def commit(self) -> None:
        self.conn.commit()
