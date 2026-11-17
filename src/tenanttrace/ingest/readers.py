"""Streaming readers that keep a pointer to every raw record.

Each reader yields `RawRecord`s carrying the record's raw text, its first and last physical
line in the file (1-based), the byte offset of its first character where the encoding allows
it (UTF-8 and single-byte encodings), and the SHA-256 of the raw text. Nothing is read into
memory beyond the current record and a bounded buffer, so multi-gigabyte exports stream.

Encodings handled: UTF-8 with or without BOM, UTF-16 LE/BE with BOM, UTF-16 LE without BOM
(detected from NUL bytes), and cp1252 as the fallback for bytes that are not valid UTF-8.
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
from typing import Iterator

from tenanttrace.hashing import sha256_text

csv.field_size_limit(min(sys.maxsize, 2**31 - 1))

SNIFF_BYTES = 64 * 1024


@dataclass
class RawRecord:
    text: str
    line_start: int
    line_end: int
    byte_offset: int | None
    sha256: str


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
        if exc.start >= len(head) - 4:
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
        with open(path, "rb") as fh:
            fh.seek(enc.bom)
            text = io.TextIOWrapper(fh, encoding=enc.name, errors="replace", newline="")
            n = 0
            for line in text:
                n += 1
                yield n, line, None


@dataclass
class CsvRow:
    fields: list[str]
    raw: RawRecord


def iter_csv(path: Path, enc: Encoding) -> Iterator[CsvRow]:
    """Stream CSV rows (header row included as the first yielded row).

    A PowerShell `#TYPE ...` preamble line is yielded as a row with a single field so the
    caller can recognise and skip it explicitly.
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
        first = buf[0]
        text = "".join(b[1] for b in buf)
        rec = RawRecord(text=text, line_start=first[0], line_end=buf[-1][0], byte_offset=first[2],
                        sha256=sha256_text(text.rstrip("\r\n")))
        buf.clear()
        if not fields or (len(fields) == 1 and fields[0].strip() == ""):
            continue  # blank line
        yield CsvRow(fields=fields, raw=rec)


@dataclass
class JsonItem:
    obj: object | None      # None when the record could not be decoded
    raw: RawRecord
    error: str = ""


_ws = " \t\r\n,"
MAX_RECORD_CHARS = 32 * 1024 * 1024
_RESYNC = re.compile(r"\n[ \t]*\{")


def iter_json(path: Path, enc: Encoding, chunk_chars: int = 1 << 20) -> Iterator[JsonItem]:
    """Stream records from a JSON array, JSON Lines, or concatenated JSON objects.

    Uses `json.JSONDecoder.raw_decode` on a sliding buffer so that each record is parsed by
    the C decoder. Line numbers are tracked by counting newlines in consumed text. A Graph
    style wrapper object (`{"value": [...]}`) is expanded into its items, all pointing at the
    wrapper's line range with their index noted.
    """
    decoder = json.JSONDecoder()
    with open(path, "rb") as fh:
        fh.seek(enc.bom)
        text_stream = io.TextIOWrapper(fh, encoding=enc.name, errors="replace", newline="")
        buf = ""
        pos = 0
        line = 1           # line number at buf[pos]
        byte_pos = enc.bom  # byte offset at buf[pos] (only meaningful if enc.byte_offsets)
        eof = False
        in_array = None    # None = undecided, True = inside top-level array, False = object stream
        array_closed = False

        def refill() -> bool:
            nonlocal buf, pos, eof
            if eof:
                return False
            chunk = text_stream.read(chunk_chars)
            if not chunk:
                eof = True
                return False
            buf = buf[pos:] + chunk
            pos = 0
            return True

        def advance(n: int) -> None:
            nonlocal pos, line, byte_pos
            seg = buf[pos:pos + n]
            line += seg.count("\n")
            if enc.byte_offsets:
                byte_pos += len(seg.encode(enc.name, errors="replace"))
            pos += n

        refill()
        while True:
            # skip whitespace and separators
            while True:
                while pos < len(buf) and buf[pos] in _ws:
                    advance(1)
                if pos < len(buf) or not refill():
                    break
            if pos >= len(buf):
                break
            ch = buf[pos]
            if in_array is None:
                if ch == "[":
                    in_array = True
                    advance(1)
                    continue
                in_array = False
            if ch == "]" and in_array:
                array_closed = True
                advance(1)
                continue
            # decode one value starting at pos
            bad: str | None = None
            while True:
                try:
                    obj, end = decoder.raw_decode(buf, pos)
                    break
                except json.JSONDecodeError as exc:
                    # an incomplete record at the end of the buffer: read more, up to a bound
                    if len(buf) - pos < MAX_RECORD_CHARS and refill():
                        continue
                    bad = exc.msg
                    break
            if bad is not None:
                # malformed (or truncated at EOF): emit it as one unparseable record and resync
                m = _RESYNC.search(buf, pos + 1)
                stop = m.start() + 1 if m else len(buf)
                rest = buf[pos:stop]
                rec = RawRecord(rest, line, line + rest.count("\n"),
                                byte_pos if enc.byte_offsets else None, sha256_text(rest))
                yield JsonItem(None, rec, f"undecodable JSON ({bad})" + ("" if m else " at end of file"))
                advance(len(rest))
                continue
            raw_text = buf[pos:end]
            start_line = line
            start_byte = byte_pos if enc.byte_offsets else None
            end_line = start_line + raw_text.count("\n")
            rec = RawRecord(raw_text, start_line, end_line, start_byte, sha256_text(raw_text))
            advance(end - pos)
            if (isinstance(obj, dict) and isinstance(obj.get("value"), list)
                    and any(k.startswith("@odata") for k in obj)):
                for i, item in enumerate(obj["value"]):
                    item_text = json.dumps(item, sort_keys=True, ensure_ascii=False)
                    sub = RawRecord(item_text, start_line, end_line, start_byte, sha256_text(item_text))
                    yield JsonItem(item, sub, f"value[{i}] of a Graph response wrapper")
                continue
            if isinstance(obj, list) and not in_array:
                for i, item in enumerate(obj):
                    item_text = json.dumps(item, sort_keys=True, ensure_ascii=False)
                    yield JsonItem(item, RawRecord(item_text, start_line, end_line, start_byte,
                                                   sha256_text(item_text)), f"[{i}] of nested array")
                continue
            yield JsonItem(obj, rec)
        _ = array_closed
