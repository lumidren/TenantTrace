from __future__ import annotations

import codecs
import json
from pathlib import Path

import pytest

from tenanttrace.ingest.readers import detect_encoding, iter_csv, iter_json, read_head
from tenanttrace.ingest.timeparse import TimeParseError, parse_ts


def _enc(p: Path):
    return detect_encoding(read_head(p))


CSV_TEXT = 'A,B,C\r\n1,"two\r\nlines",3\r\n4,"{""k"": ""v, w""}",6\r\n'


@pytest.mark.parametrize(
    "encoding,bom,offsets",
    [("utf-8", b"", True), ("utf-8", codecs.BOM_UTF8, True), ("utf-16-le", codecs.BOM_UTF16_LE, False),
     ("utf-16-be", codecs.BOM_UTF16_BE, False), ("utf-16-le", b"", False)],
)
def test_csv_records_keep_line_pointers_in_any_encoding(tmp_path, encoding, bom, offsets):
    p = tmp_path / "f.csv"
    p.write_bytes(bom + CSV_TEXT.encode(encoding))
    enc = _enc(p)
    rows = list(iter_csv(p, enc))
    assert [r.fields for r in rows] == [["A", "B", "C"], ["1", "two\r\nlines", "3"], ["4", '{"k": "v, w"}', "6"]]
    assert [(r.raw.line_start, r.raw.line_end) for r in rows] == [(1, 1), (2, 3), (4, 4)]
    if offsets:
        data = p.read_bytes()
        for r in rows:
            assert data[r.raw.byte_offset:].decode("utf-8").startswith(r.raw.text)
    else:
        assert all(r.raw.byte_offset is None for r in rows)


def test_cp1252_fallback(tmp_path):
    p = tmp_path / "f.csv"
    p.write_bytes("Name,City\r\nJos\xe9,M\xfcnchen\r\n".encode("cp1252"))
    enc = _enc(p)
    assert enc.name == "cp1252"
    rows = list(iter_csv(p, enc))
    assert rows[1].fields == ["José", "München"]


def _json_variants():
    recs = [{"id": i, "msg": "line\nbreak" if i == 1 else "x"} for i in range(3)]
    pretty = json.dumps(recs, indent=2)
    lines = "\n".join(json.dumps(r) for r in recs) + "\n"
    return recs, {"array": pretty, "jsonl": lines,
                  "graph": json.dumps({"@odata.context": "x", "value": recs})}


@pytest.mark.parametrize("kind", ["array", "jsonl", "graph"])
def test_json_shapes(tmp_path, kind):
    recs, variants = _json_variants()
    p = tmp_path / "f.json"
    p.write_text(variants[kind], encoding="utf-8")
    items = list(iter_json(p, _enc(p), chunk_chars=16))  # tiny chunks force refills
    assert [i.obj for i in items] == recs
    if kind == "jsonl":
        assert [i.raw.line_start for i in items] == [1, 2, 3]
    if kind == "array":
        text = p.read_text(encoding="utf-8")
        for it in items:
            assert text.splitlines()[it.raw.line_start - 1].strip().startswith("{")
            data = p.read_bytes()
            assert data[it.raw.byte_offset:].decode().startswith(it.raw.text)


def test_json_malformed_record_is_reported_and_stream_resyncs(tmp_path):
    p = tmp_path / "f.jsonl"
    p.write_text('{"a": 1}\n{"a": 2, broken\n{"a": 3}\n', encoding="utf-8")
    items = list(iter_json(p, _enc(p)))
    assert [i.obj for i in items] == [{"a": 1}, None, {"a": 3}]
    assert items[1].error.startswith("undecodable JSON")
    assert items[1].raw.line_start == 2
    assert items[2].raw.line_start == 3


def test_json_truncated_at_eof(tmp_path):
    p = tmp_path / "f.json"
    p.write_text('[{"a": 1},\n {"a": 2, "b": "unterminated', encoding="utf-8")
    items = list(iter_json(p, _enc(p)))
    assert items[0].obj == {"a": 1}
    assert items[1].obj is None and "end of file" in items[1].error


def test_empty_files(tmp_path):
    p = tmp_path / "e.json"
    p.write_bytes(b"")
    assert list(iter_json(p, _enc(p))) == []
    assert list(iter_csv(p, _enc(p))) == []


@pytest.mark.parametrize(
    "value,expected,note_part",
    [
        ("2026-10-25T00:30:00Z", "2026-10-25T00:30:00.000000Z", "with zone"),
        ("2026-10-25T01:30:00.1234567Z", "2026-10-25T01:30:00.123456Z", "with zone"),
        ("2026-10-25T02:30:00+01:00", "2026-10-25T01:30:00.000000Z", "offset"),
        ("2026-10-25T02:30:00", "2026-10-25T02:30:00.000000Z", "documents UTC"),
        ("10/26/2026 3:15:02 PM", "2026-10-26T15:15:02.000000Z", "M/D/Y"),
        ("26/10/2026 15:15:02", "2026-10-26T15:15:02.000000Z", "D/M/Y"),
        ("3/4/2026 12:05:00 AM", "2026-03-04T00:05:00.000000Z", "ambiguous"),
        ("/Date(1793000000000)/", "2026-10-26T", "epoch"),
    ],
)
def test_parse_ts(value, expected, note_part):
    iso, note = parse_ts(value)
    assert iso.startswith(expected)
    assert note_part in note


def test_parse_ts_across_dst_change_is_monotonic():
    # UK clocks went back at 01:00 UTC on 2026-10-25: 01:30+01:00 and 01:30+00:00 are an hour apart
    a, _ = parse_ts("2026-10-25T01:30:00+01:00")
    b, _ = parse_ts("2026-10-25T01:30:00+00:00")
    assert a == "2026-10-25T00:30:00.000000Z" and b == "2026-10-25T01:30:00.000000Z"


@pytest.mark.parametrize("bad", ["", "yesterday", "2026-13-45T00:00:00Z", "31/31/2026 10:00"])
def test_parse_ts_rejects_garbage(bad):
    with pytest.raises((TimeParseError, ValueError)):
        parse_ts(bad)


@pytest.mark.parametrize("encoding,bom", [("utf-8", b""), ("utf-8", codecs.BOM_UTF8), ("utf-16-le", codecs.BOM_UTF16_LE)])
def test_read_span_round_trips_every_record(tmp_path, encoding, bom):
    from tenanttrace.ingest.readers import read_spans

    recs = [{"id": i, "text": "multi\nline" if i % 2 else "x", "ü": "é"} for i in range(5)]
    p = tmp_path / "f.json"
    p.write_bytes(bom + json.dumps(recs, indent=4).replace("\n", "\r\n").encode(encoding))
    enc = _enc(p)
    items = list(iter_json(p, enc, chunk_chars=37))
    spans = {(i.raw.line_start, i.raw.col_start, i.raw.line_end, i.raw.col_end): i for i in items}
    texts = read_spans(p, enc, spans.keys())
    for span, item in spans.items():
        assert texts[span] == item.raw.text
        assert json.loads(texts[span]) == item.obj

    c = tmp_path / "f.csv"
    c.write_bytes(bom + CSV_TEXT.encode(encoding))
    enc = _enc(c)
    rows = list(iter_csv(c, enc))
    got = read_spans(c, enc, [(r.raw.line_start, r.raw.col_start, r.raw.line_end, r.raw.col_end) for r in rows])
    for r in rows:
        assert got[(r.raw.line_start, r.raw.col_start, r.raw.line_end, r.raw.col_end)] == r.raw.text


def test_concatenated_arrays_are_read_as_one_stream(tmp_path):
    p = tmp_path / "pages.json"
    p.write_text('[{"a": 1}, {"a": 2}]\r\n[{"a": 3}]\r\n', encoding="utf-8")
    assert [i.obj for i in iter_json(p, _enc(p))] == [{"a": 1}, {"a": 2}, {"a": 3}]
