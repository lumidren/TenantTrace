"""Refuse every network operation for the life of the process.

TenantTrace is offline by design. Rather than trusting that no code path (ours or a
dependency's) ever opens a socket, the CLI installs a Python audit hook that raises on
socket creation, connection and name resolution. Audit hooks cannot be removed once
installed, so the guard holds for the whole run.
"""

from __future__ import annotations

import sys

_BLOCKED_EVENTS = frozenset(
    {
        "socket.__new__",
        "socket.connect",
        "socket.bind",
        "socket.getaddrinfo",
        "socket.gethostbyname",
        "socket.gethostbyaddr",
        "socket.sendto",
        "urllib.Request",
        "http.client.connect",
    }
)

_installed = False


class NetworkBlocked(RuntimeError):
    """Raised when anything in the process tries to use the network."""


def _hook(event: str, args: tuple) -> None:  # pragma: no cover - exercised via subprocess test
    if event in _BLOCKED_EVENTS:
        raise NetworkBlocked(f"TenantTrace is offline: blocked network operation {event!r}")


def install() -> None:
    """Install the guard once. Safe to call repeatedly."""
    global _installed
    if _installed:
        return
    sys.addaudithook(_hook)
    _installed = True


def is_installed() -> bool:
    return _installed
