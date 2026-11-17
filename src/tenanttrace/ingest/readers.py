"""Streaming readers that keep a pointer to every raw record.

Each reader yields `RawRecord`s carrying the record's exact text and its span in the file:
first and last physical line (1-based), the character column where it starts and ends, the
byte offset of its first character where the encoding allows it (UTF-8 and single-byte
encodings), and the SHA-256 of the text. `read_raw` re-reads a span from the file so that any
normalized event can be traced back to, and re-verified against, the original record.

Nothing is held in memory beyond the current record and a bounded buffer, so multi-gigabyte
exports stream.

Encodings handled: UTF-8 with or without BOM, UTF-16 LE/BE with BOM, UTF-16 LE/BE without BOM
(detected from NUL bytes), UTF-32 with BOM, and Windows-1252 as the fallback for bytes that are
not valid UTF-8.

Record hashes are computed over the decoded record text re-encoded as UTF-8, so the same
record has the same hash whatever encoding the export used. The file as a whole is hashed over
its bytes (see the manifest).
"""

from __future__ import annotations

import codecs
import csv
import io
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

from tenanttrace.hashing import sha256_text

csv.field_size_limit(min(sys.maxsize, 2**31 - 1))

SNIFF_BYTES = 64 * 1024


@dataclass
class RawRecord:
    text: str
    line_start: int
    col_start: int
    line_end: int
    col_end: int
    byte_offset: int | None
    sha256: str
    exact: bool = True      # False when the text is a re-serialisation (items of a wrapper object)


@dataclass
class Encoding:
    name: str            # python codec name used to decode
    bom: int             # number of BOM bytes at the start of the file
    byte_offsets: bool   # whether byte offsets can be computed per line
    note: str = ""


def detect_encoding(head: bytes) -> Encoding:
    if head.startswith(codecs.BOM_UTF8):
        return Encoding("utf-8", 3, True, "UTF-8 with BOM")
    if head.startswith(codecs.BOM_UTF32_LE) or head.startswith(codecs.BOM_UTF32_BE):
        return Encoding("utf-32", 4, False, "UTF-32 with BOM")
    if head.startswith(codecs.BOM_UTF16_LE):
        return Encoding("utf-16-le", 2, False, "UTF-16 LE with BOM")
    if head.startswith(codecs.BOM_UTF16_BE):
        return Encoding("utf-16-be", 2, False, "UTF-16 BE with BOM")
    sample = head[:4096]
    if len(sample) >= 4:
        odd_nuls = sample[1::2].count(0)
        even_nuls = sample[0::2].count(0)
        half = len(sample) // 2
        if odd_nuls > half * 0.4 and even_nuls < half * 0.05:
            return Encoding("utf-16-le", 0, False, "UTF-16 LE without BOM (detected from NUL bytes)")
        if even_nuls > half * 0.4 and odd_nuls < half * 0.05:
            return Encoding("utf-16-be", 0, False, "UTF-16 BE without BOM (detected from NUL bytes)")
    try:
        head.decode("utf-8")
        return Encoding("utf-8", 0, True, "UTF-8")
    except UnicodeDecodeError as exc:
        # a multi-byte sequence cut at the end of the sniff window is still UTF-8
        if exc.start >= len(head) - 4 and len(head) >= SNIFF_BYTES - 4:
            return Encoding("utf-8", 0, True, "UTF-8")
        return Encoding("cp1252", 0, True, "not valid UTF-8; decoded as Windows-1252")


def read_head(path: Path, n: int = SNIFF_BYTES) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(n)


def head_text(path: Path, enc: Encoding, n: int = SNIFF_BYTES) -> str:
    raw = read_head(path, n)[enc.bom:]
    return raw.decode(enc.name, errors="replace")


def iter_lines(path: Path, enc: Encoding) -> Iterator[tuple[int, str, int | None]]:
    """Yield (line_number, line_text_with_newline, byte_offset_or_None)."""
    if enc.byte_offsets:
        with open(path, "rb") as fh:
            fh.seek(enc.bom)
            offset = enc.bom
            n = 0
            for raw in fh:
                n += 1
                yield n, raw.decode(enc.name, errors="replace"), offset
                offset += len(raw)
    else:
        # split on "\n" only, exactly like the byte-oriented path and the JSON line counter
        with open(path, "rb") as fh:
            fh.seek(enc.bom)
            stream = io.TextIOWrapper(fh, encoding=enc.name, errors="replace", newline="")
            n = 0
            pending = ""
            while True:
                chunk = stream.read(1 << 16)
                if not chunk:
                    break
                parts = (pending + chunk).split("\n")
                pending = parts.pop()
                for p in parts:
                    n += 1
                    yield n, p + "\n", None
            if pending:
                n += 1
                yield n, pending, None


def _strip_nl(s: str) -> str:
    return s.rstrip("\r\n")


# ----------------------------------------------------------------------------- CSV


@dataclass
class CsvRow:
    fields: list[str]
    raw: RawRecord


def iter_csv(path: Path, enc: Encoding) -> Iterator[CsvRow]:
    """Stream CSV rows (the header row is the first row yielded).

    A record's raw text is its physical lines without the final line break. A PowerShell
    `#TYPE ...` preamble line is yielded as a one-field row so the caller can skip it
    explicitly. Blank lines are skipped.
    """
    buf: list[tuple[int, str, int | None]] = []
    lines = iter_lines(path, enc)

    def feeder() -> Iterator[str]:
        for item in lines:
            buf.append(item)
            yield item[1]

    reader = csv.reader(feeder(), strict=False)
    for fields in reader:
        if not buf:
            continue
        first, last = buf[0], buf[-1]
        text = _strip_nl("".join(b[1] for b in buf))
        rec = RawRecord(text=text, line_start=first[0], col_start=0, line_end=last[0],
                        col_end=len(_strip_nl(last[1])), byte_offset=first[2], sha256=sha256_text(text))
        buf.clear()
        if not fields or (len(fields) == 1 and fields[0].strip() == ""):
            continue  # blank line
        yield CsvRow(fields=fields, raw=rec)


# ----------------------------------------------------------------------------- JSON


@dataclass
class JsonItem:
    obj: object | None      # None when the record could not be decoded
    raw: RawRecord
    note: str = ""          # where the item sits (e.g. "value[3] of a Graph response wrapper")
    error: str = ""


_WS = " \t\r\n,"
MAX_RECORD_CHARS = 32 * 1024 * 1024
_RESYNC = re.compile(r"\n[ \t]*[\[{]")


def iter_json(path: Path, enc: Encoding, chunk_chars: int = 1 << 20) -> Iterator[JsonItem]:
    """Stream records from a JSON array, several concatenated arrays, JSON Lines, or
    concatenated JSON objects.

    Each record is decoded by the C JSON decoder (`raw_decode`) from a sliding buffer. Line,
    column and byte positions are tracked through the consumed text. A Graph response wrapper
    (`{"@odata...": ..., "value": [...]}`) is expanded into its items; their raw text is a
    re-serialisation, marked `exact=False`, pointing at the wrapper's span.
    """
    decoder = json.JSONDecoder()
    with open(path, "rb") as fh:
        fh.seek(enc.bom)
        stream = io.TextIOWrapper(fh, encoding=enc.name, errors="replace", newline="")
        st = {"buf": "", "pos": 0, "line": 1, "col": 0, "byte": enc.bom, "eof": False}

        def refill() -> bool:
            if st["eof"]:
                return False
            chunk = stream.read(chunk_chars)
            if not chunk:
                st["eof"] = True
                return False
            st["buf"] = st["buf"][st["pos"]:] + chunk
            st["pos"] = 0
            return True

        def advance(n: int) -> None:
            seg = st["buf"][st["pos"]:st["pos"] + n]
            nl = seg.count("\n")
            if nl:
                st["line"] += nl
                st["col"] = len(seg) - seg.rfind("\n") - 1
            else:
                st["col"] += len(seg)
            if enc.byte_offsets:
                st["byte"] += len(seg.encode(enc.name, errors="replace"))
            st["pos"] += n

        def make_raw(text: str) -> RawRecord:
            nl = text.count("\n")
            line_end = st["line"] + nl
            col_end = (len(text) - text.rfind("\n") - 1) if nl else st["col"] + len(text)
            return RawRecord(text, st["line"], st["col"], line_end, col_end,
                             st["byte"] if enc.byte_offsets else None, sha256_text(text))

        refill()
        in_array = False
        while True:
            while True:
                buf, pos = st["buf"], st["pos"]
                while pos < len(buf) and buf[pos] in _WS:
                    pos += 1
                if pos > st["pos"]:
                    advance(pos - st["pos"])
                if st["pos"] < len(st["buf"]) or not refill():
                    break
            if st["pos"] >= len(st["buf"]):
                break
            ch = st["buf"][st["pos"]]
            if ch == "[" and not in_array:
                in_array = True
                advance(1)
                continue
            if ch == "]" and in_array:
                in_array = False      # another top-level array may follow (appended pages)
                advance(1)
                continue
            bad: str | None = None
            while True:
                try:
                    obj, end = decoder.raw_decode(st["buf"], st["pos"])
                    break
                except json.JSONDecodeError as exc:
                    if len(st["buf"]) - st["pos"] < MAX_RECORD_CHARS and refill():
                        continue
                    bad = exc.msg
                    break
            if bad is not None:
                buf, pos = st["buf"], st["pos"]
                m = _RESYNC.search(buf, pos + 1)
                stop = m.start() + 1 if m else len(buf)
                rest = buf[pos:stop].rstrip()
                rec = make_raw(rest)
                yield JsonItem(None, rec, error=f"undecodable JSON ({bad})" + ("" if m else " at end of file"))
                advance(stop - pos)
                continue
            raw_text = st["buf"][st["pos"]:end]
            rec = make_raw(raw_text)
            advance(end - st["pos"])
            if isinstance(obj, dict) and isinstance(obj.get("value"), list) and any(k.startswith("@odata") for k in obj):
                for i, item in enumerate(obj["value"]):
                    t = json.dumps(item, sort_keys=True, ensure_ascii=False)
                    sub = RawRecord(t, rec.line_start, rec.col_start, rec.line_end, rec.col_end, rec.byte_offset,
                                    sha256_text(t), exact=False)
                    yield JsonItem(item, sub, note=f"value[{i}] of a Graph response wrapper")
                continue
            if isinstance(obj, list):
                for i, item in enumerate(obj):
                    t = json.dumps(item, sort_keys=True, ensure_ascii=False)
                    sub = RawRecord(t, rec.line_start, rec.col_start, rec.line_end, rec.col_end, rec.byte_offset,
                                    sha256_text(t), exact=False)
                    yield JsonItem(item, sub, note=f"[{i}] of a nested array")
                continue
            yield JsonItem(obj, rec)


# ----------------------------------------------------------------------------- re-reading


def read_spans(path: Path, enc: Encoding, spans: Iterable[tuple[int, int, int, int]]) -> dict[tuple[int, int, int, int], str]:
    """Re-read several (line_start, col_start, line_end, col_end) spans in one pass."""
    wanted = sorted(set(spans))
    if not wanted:
        return {}
    out: dict[tuple[int, int, int, int], str] = {}
    max_line = max(s[2] for s in wanted)
    lines: dict[int, str] = {}
    needed: set[int] = set()
    for s in wanted:
        needed.update(range(s[0], s[2] + 1))
    for n, text, _ in iter_lines(path, enc):
        if n in needed:
            lines[n] = text
        if n >= max_line:
            break
    for s in wanted:
        l0, c0, l1, c1 = s
        if l0 not in lines or l1 not in lines:
            continue
        if l0 == l1:
            out[s] = lines[l0][c0:c1]
        else:
            parts = [lines[l0][c0:]] + [lines[i] for i in range(l0 + 1, l1)] + [lines[l1][:c1]]
            out[s] = "".join(parts)
    return out


def read_span(path: Path, enc: Encoding, line_start: int, col_start: int, line_end: int, col_end: int) -> str | None:
    return read_spans(path, enc, [(line_start, col_start, line_end, col_end)]).get(
        (line_start, col_start, line_end, col_end))
