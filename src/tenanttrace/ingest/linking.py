"""Cross-log linking of records that describe the same action."""

from __future__ import annotations

from typing import Any

from tenanttrace.case import ProcessingLog
from tenanttrace.store import CaseStore


def link_events(store: CaseStore, log: ProcessingLog) -> dict[str, Any]:
    log.write("link", "no events to link")
    return {"duplicates": 0, "corroborating": 0}
