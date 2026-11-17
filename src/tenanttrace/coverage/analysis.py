"""Evidence coverage (phase 1 placeholder: counts only)."""

from __future__ import annotations

from typing import Any

from tenanttrace.case import ProcessingLog
from tenanttrace.store import CaseStore


def compute_coverage(store: CaseStore, params: dict[str, Any], log: ProcessingLog) -> dict[str, Any]:
    n = store.count()
    return {"summary": {"events": n, "sources_present": 0}, "sources": [], "gaps": []}
