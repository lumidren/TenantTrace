"""Hashing helpers. Inputs are only ever opened read-only, in binary mode."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

CHUNK = 1024 * 1024


def long_path(path: Path) -> Path:
    """On Windows, use the extended-length form so paths over 260 characters still open.

    Collector output nests folders deeply (for example Microsoft-Extractor-Suite's
    `Output/EntraID/<timestamp>-SignInLogs/interactiveUser & nonInteractiveUser/...`), which can
    exceed the classic Windows path limit without the system-wide long-path setting.
    """
    if os.name != "nt":
        return Path(path)
    s = str(Path(path).resolve())
    if s.startswith(EXTENDED):
        return Path(s)
    if s.startswith("\\\\"):
        return Path(EXTENDED_UNC + s[2:])
    return Path(EXTENDED + s)


EXTENDED = "\\\\?\\"
EXTENDED_UNC = "\\\\?\\UNC\\"


def display_path(path: Path) -> str:
    s = str(path)
    if s.startswith(EXTENDED_UNC):
        return "\\\\" + s[len(EXTENDED_UNC):]
    if s.startswith(EXTENDED):
        return s[len(EXTENDED):]
    return s


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:  # read-only by construction
        while True:
            block = fh.read(CHUNK)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def short_id(*parts: str, length: int = 16) -> str:
    """Deterministic identifier from string parts."""
    h = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()
    return h[:length]
