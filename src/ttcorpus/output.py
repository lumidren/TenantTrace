"""Write generated exports and their ground truth to disk."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any, Iterable


def write_csv(path: Path, header: list[str], rows: Iterable[list[Any]], encoding: str = "utf-8-sig",
              preamble: str | None = None, newline: str = "\r\n") -> int:
    """Write a CSV the way Windows tools do: CRLF line ends, every field quoted, optional BOM."""
    path.parent.mkdir(parents=True, exist_ok=True)
    buf = io.StringIO()
    w = csv.writer(buf, quoting=csv.QUOTE_ALL, lineterminator=newline)
    if preamble:
        buf.write(preamble + newline)
    w.writerow(header)
    n = 0
    for r in rows:
        w.writerow(["" if v is None else v for v in r])
        n += 1
    data = buf.getvalue()
    if encoding in ("utf-16-le", "utf-16le"):
        raw = b"\xff\xfe" + data.encode("utf-16-le")
    elif encoding == "utf-8-sig":
        raw = b"\xef\xbb\xbf" + data.encode("utf-8")
    else:
        raw = data.encode(encoding)
    path.write_bytes(raw)
    return n


def write_json_array(path: Path, items: list[dict[str, Any]], indent: int | None = 2) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(items, fh, indent=indent, ensure_ascii=False)
        fh.write("\n")
    return len(items)


def write_jsonl(path: Path, items: list[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for it in items:
            fh.write(json.dumps(it, ensure_ascii=False) + "\n")
    return len(items)
