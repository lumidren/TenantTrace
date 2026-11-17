from __future__ import annotations

import socket
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def no_network(monkeypatch):
    """Fail the test if anything opens a socket or resolves a name."""
    attempts: list[str] = []

    def deny(name):
        def _f(*a, **k):
            attempts.append(name)
            raise AssertionError(f"network use attempted: {name}")
        return _f

    monkeypatch.setattr(socket.socket, "connect", deny("socket.connect"))
    monkeypatch.setattr(socket.socket, "connect_ex", deny("socket.connect_ex"))
    monkeypatch.setattr(socket, "create_connection", deny("create_connection"))
    monkeypatch.setattr(socket, "getaddrinfo", deny("getaddrinfo"))
    return attempts
