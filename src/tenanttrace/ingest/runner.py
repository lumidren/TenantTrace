"""Run the right parser over one input file and store what it yields."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tenanttrace.case import ProcessingLog, Timer
from tenanttrace.ingest.parsers import ParseState, Sample, choose
from tenanttrace.ingest.readers import detect_encoding, iter_csv, iter_json, read_head
from tenanttrace.store import CaseStore

BOM = chr(0xFEFF)
BOM_WS = BOM + " " + chr(9) + chr(13) + chr(10)
NL = chr(10)
SEPARATORS = (",", chr(9), ";")


def build_sample(path: Path, rel: str, size: int) -> tuple[Sample, Any]:
    if size == 0:
        return Sample(rel=rel, shape="empty"), None
    head = read_head(path)
    enc = detect_encoding(head)
    text = head[enc.bom:].decode(enc.name, errors="replace").lstrip("\ufeff \t\r\n")
    if not text:
        return Sample(rel=rel, shape="empty"), enc
    if "\x00" in text[:2000]:
        return Sample(rel=rel, shape="binary"), enc
    if text[0] in "[{":
        first = None
        n = 0
        for item in iter_json(path, enc):
            n += 1
            if item.obj is not None:
                first = item.obj
                break
            if n >= 5:
                break
        return Sample(rel=rel, shape="json", first_obj=first), enc
    lines = text.split(NL, 2)
    first_line = lines[1] if lines[0].startswith("#TYPE") and len(lines) > 1 else lines[0]
    if not any(sep in first_line for sep in SEPARATORS):
        return Sample(rel=rel, shape="text"), enc
    header: list[str] = []
    preamble = ""
    for row in iter_csv(path, enc):
        if len(row.fields) == 1 and row.fields[0].startswith("#TYPE"):
            preamble = row.fields[0]
            continue
        header = [h.strip().lstrip(BOM) for h in row.fields]
        break
    return Sample(rel=rel, shape="csv", header=header, preamble=preamble), enc


def ingest_file(path: Path, rel: str, file_id: int, file_sha: str, size: int, store: CaseStore,
                log: ProcessingLog) -> dict[str, Any]:
    timer = Timer()
    sample, enc = build_sample(path, rel, size)
    base = {"parser": None, "parser_reason": "", "encoding": enc.note if enc else "", "records_total": 0,
            "records_parsed": 0, "records_unrecognised": 0, "records_malformed": 0, "info": {}}
    if sample.shape == "empty":
        base["parser_reason"] = "empty file"
        log.write("detect", f"{rel}: empty file, nothing to parse", file_id=file_id)
        store.update_file(file_id, parser=None, parser_reason="empty file", encoding=base["encoding"])
        return base
    parser, reason, scores = choose(sample)
    if parser is None:
        why = "; ".join(f"{k}: {v['reason']}" for k, v in scores.items() if v["score"] > 0) or "no parser matched"
        base["parser_reason"] = f"no parser recognised this file ({sample.shape}); {why}"
        log.write("detect", f"{rel}: not recognised; the whole file is reported as unrecognised", file_id=file_id,
                  shape=sample.shape, scores=scores)
        store.update_file(file_id, parser=None, parser_reason=base["parser_reason"], encoding=base["encoding"])
        return base
    log.write("detect", f"{rel}: parser {parser.id} ({reason}); encoding {enc.note}", file_id=file_id,
              scores={k: v["score"] for k, v in scores.items()})

    def sink(events):
        store.insert_events(events)

    st = ParseState(path, rel, file_id, file_sha, enc, parser.id, sink, store.add_unrecognised)
    parser.parse(st)
    st.flush()
    info = st.info()
    info["container"] = parser.container
    info["parse_seconds"] = timer.elapsed()
    result = {
        "parser": parser.id,
        "parser_title": parser.title,
        "parser_reason": reason,
        "encoding": enc.note,
        "records_total": st.total,
        "records_parsed": st.parsed,
        "records_unrecognised": st.unrecognised,
        "records_malformed": st.malformed,
        "info": info,
    }
    store.update_file(file_id, parser=parser.id, parser_reason=reason, encoding=enc.note,
                      records_total=st.total, records_parsed=st.parsed, records_unrecognised=st.unrecognised,
                      records_malformed=st.malformed, info=json.dumps(info, sort_keys=True))
    log.write("parse", f"{rel}: {st.parsed} event(s) from {st.total} record(s); {st.unrecognised} unrecognised, "
                       f"{st.malformed} malformed", file_id=file_id, sources=info["events_by_source"],
              truncation=len(info["truncation"]), seconds=info["parse_seconds"])
    if info["unmapped_total"]:
        log.write("parse", f"{rel}: {info['unmapped_total']} record(s) with operations TenantTrace does not map; "
                           "kept as category 'other'", file_id=file_id, operations=info["unmapped_operations"])
    return result
