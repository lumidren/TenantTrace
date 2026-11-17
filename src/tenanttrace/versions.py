"""Versions of the data files that determine results: the rule set and the gap reference table."""

from __future__ import annotations

from functools import lru_cache
from importlib import resources

import yaml


@lru_cache(maxsize=None)
def reference_version() -> str:
    try:
        text = resources.files("tenanttrace.reference").joinpath("gap_reference.yaml").read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError):
        return "none"
    data = yaml.safe_load(text) or {}
    return str(data.get("version", "unversioned"))


@lru_cache(maxsize=None)
def ruleset_version() -> str:
    try:
        text = resources.files("tenanttrace.rules").joinpath("ruleset.yaml").read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError):
        return "none"
    data = yaml.safe_load(text) or {}
    return str(data.get("version", "unversioned"))
