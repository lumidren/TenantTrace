"""Loader for the versioned gap reference table (reference/gap_reference.yaml)."""

from __future__ import annotations

from functools import lru_cache
from importlib import resources
from typing import Any

import yaml

REQUIRED = ("id", "title", "records", "licence", "retention", "default_on", "citations", "last_checked", "verified")


class Reference:
    def __init__(self, data: dict[str, Any]):
        self.version = str(data["version"])
        self.title = data.get("title", "")
        self.sources: list[dict[str, Any]] = data["sources"]
        self._by_id = {s["id"]: s for s in self.sources}
        for s in self.sources:
            missing = [k for k in REQUIRED if k not in s]
            if missing:
                raise ValueError(f"reference entry {s.get('id')} is missing {missing}")

    def ids(self) -> list[str]:
        return [s["id"] for s in self.sources]

    def has(self, sid: str) -> bool:
        return sid in self._by_id

    def entry(self, sid: str) -> dict[str, Any]:
        return self._by_id[sid]

    def cite(self, sid: str) -> list[dict[str, Any]]:
        return list(self._by_id[sid].get("citations", [])) if sid in self._by_id else []

    def rules_for(self, sid: str) -> list[str]:
        """Rule ids whose required sources include `sid` (empty when no rule set is installed)."""
        try:
            from tenanttrace.rules.engine import load_rules

            _, rules = load_rules()
        except (ImportError, FileNotFoundError):
            return []
        out = []
        for r in rules:
            spec = r.sources_spec()
            if sid in spec.get("all", []) or sid in spec.get("any", []):
                out.append(r.id)
        return sorted(out)


@lru_cache(maxsize=None)
def _load() -> Reference:
    text = resources.files("tenanttrace.reference").joinpath("gap_reference.yaml").read_text(encoding="utf-8")
    return Reference(yaml.safe_load(text))


def load_reference() -> Reference:
    return _load()
