"""Run the right parser over one input file and store what it yields."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from tenanttrace.case import ProcessingLog
from tenanttrace.store import CaseStore


def ingest_file(path: Path, rel: str, file_id: int, store: CaseStore, log: ProcessingLog) -> dict[str, Any]:
    # Phase 1: no parsers registered yet. Every file is recorded and hashed but not parsed.
    log.write("detect", f"no parser available for {rel}", file_id=file_id)
    store.update_file(file_id, parser=None, parser_reason="no parser registered")
    return {"parser": None, "parser_reason": "no parser registered", "records_total": 0,
            "records_parsed": 0, "records_unrecognised": 0, "records_malformed": 0}
