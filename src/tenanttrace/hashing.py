"""Hashing helpers. Inputs are only ever opened read-only, in binary mode."""

from __future__ import annotations

import hashlib
from pathlib import Path

CHUNK = 1024 * 1024


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
