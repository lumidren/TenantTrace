"""Case folder layout, manifest and processing log.

A case folder holds everything TenantTrace derives from one set of inputs:

    <case>/
      case.json          case parameters (user, window, collection time)
      manifest.json      every input file with SHA-256, size, parser chosen
      processing.log     one JSON object per line, one line per processing step
      case.sqlite        normalized events, file table, unrecognised records, analysis
      coverage.json      evidence coverage and gap analysis
      analysis.json      findings, rule run status, timeline, pivot
      report/            report.html, report.pdf, report.json

Inputs are never written to: they are opened read-only and only in binary mode.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tenanttrace import __version__

CASE_FILES = (
    "case.json",
    "manifest.json",
    "processing.log",
    "case.sqlite",
    "coverage.json",
    "analysis.json",
)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class ProcessingLog:
    """Append-only JSON-lines log of every step taken on the case."""

    def __init__(self, path: Path, echo: bool = False):
        self.path = Path(path)
        self.echo = echo
        self._seq = 0
        if self.path.exists():
            with open(self.path, "r", encoding="utf-8") as fh:
                self._seq = sum(1 for _ in fh)

    def write(self, step: str, message: str, **data: Any) -> None:
        self._seq += 1
        entry = {"seq": self._seq, "time_utc": utc_now_iso(), "step": step, "message": message}
        if data:
            entry["data"] = data
        with open(self.path, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(entry, sort_keys=True, ensure_ascii=False, default=str) + "\n")
        if self.echo:
            print(f"[{step}] {message}", flush=True)


class Case:
    def __init__(self, root: Path, echo: bool = False):
        self.root = Path(root).resolve()
        self.echo = echo

    # paths
    @property
    def db_path(self) -> Path:
        return self.root / "case.sqlite"

    @property
    def manifest_path(self) -> Path:
        return self.root / "manifest.json"

    @property
    def params_path(self) -> Path:
        return self.root / "case.json"

    @property
    def report_dir(self) -> Path:
        return self.root / "report"

    @property
    def log(self) -> ProcessingLog:
        return ProcessingLog(self.root / "processing.log", echo=self.echo)

    def create(self, force: bool = False) -> None:
        if self.root.exists() and any(self.root.iterdir()):
            known = set(CASE_FILES) | {"report"}
            present = {p.name for p in self.root.iterdir()}
            if not force:
                raise FileExistsError(
                    f"case folder {self.root} is not empty; pass --force to replace a previous TenantTrace case"
                )
            foreign = present - known
            if foreign:
                raise FileExistsError(
                    f"case folder {self.root} contains files TenantTrace did not create ({sorted(foreign)[:5]}); refusing to overwrite"
                )
            for name in present:
                p = self.root / name
                if p.is_dir():
                    for sub in sorted(p.rglob("*"), reverse=True):
                        sub.unlink() if sub.is_file() else sub.rmdir()
                    p.rmdir()
                else:
                    p.unlink()
        self.root.mkdir(parents=True, exist_ok=True)

    def write_json(self, name: str, obj: Any) -> Path:
        path = self.root / name
        tmp = path.with_suffix(path.suffix + ".tmp")
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(obj, fh, indent=2, sort_keys=True, ensure_ascii=False, default=str)
            fh.write("\n")
        os.replace(tmp, path)
        return path

    def read_json(self, name: str) -> Any:
        path = self.root / name
        if not path.exists():
            return None
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def params(self) -> dict[str, Any]:
        return self.read_json("case.json") or {}

    def save_params(self, **updates: Any) -> dict[str, Any]:
        p = self.params()
        p.update({k: v for k, v in updates.items() if v is not None})
        p.setdefault("tool_version", __version__)
        self.write_json("case.json", p)
        return p


def file_mtime_utc(path: Path) -> str:
    return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def list_inputs(input_dir: Path, exclude: Path | None = None) -> list[Path]:
    """All regular files under input_dir, in a stable order (relative POSIX path)."""
    input_dir = Path(input_dir).resolve()
    out = []
    for p in input_dir.rglob("*"):
        if not p.is_file():
            continue
        rp = p.resolve()
        if exclude is not None and (rp == exclude or exclude in rp.parents):
            continue
        out.append(p)
    out.sort(key=lambda p: p.relative_to(input_dir).as_posix())
    return out


class Timer:
    def __init__(self) -> None:
        self.t0 = time.perf_counter()

    def elapsed(self) -> float:
        return round(time.perf_counter() - self.t0, 3)
