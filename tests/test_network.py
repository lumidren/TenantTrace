"""A full run never opens a socket or resolves a name."""

from __future__ import annotations

import socket

from tenanttrace.case import Case
from tenanttrace.pipeline import run_all


def test_full_run_makes_no_network_calls(corpus_dir, tmp_path, no_network):
    case = Case(tmp_path / "case")
    run_all(corpus_dir / "demo_bec" / "exports", case, user="dana.whitfield@harborlane.example",
            collected_at="2026-11-06T17:00:00Z", pdf=True)
    assert no_network == []
    assert (case.root / "analysis.json").exists()


def test_guard_fixture_really_blocks(no_network):
    try:
        socket.create_connection(("192.0.2.1", 80), timeout=1)
    except AssertionError:
        pass
    assert no_network == ["create_connection"]
