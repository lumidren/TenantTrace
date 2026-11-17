from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from tenanttrace.case import Case
from tenanttrace.cli import main
from tenanttrace.hashing import sha256_file
from tenanttrace.store import CaseStore


def test_empty_folder_produces_valid_empty_case(tmp_path: Path):
    inp = tmp_path / "in"
    inp.mkdir()
    case_dir = tmp_path / "case"
    rc = main(["-q", "run", str(inp), "--user", "nobody@example.com", "--case", str(case_dir), "--no-pdf"])
    assert rc == 0
    manifest = json.loads((case_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["inputs"] == []
    assert manifest["totals"]["files"] == 0
    assert manifest["tool"] == "TenantTrace"
    assert (case_dir / "processing.log").read_text(encoding="utf-8").strip()
    with CaseStore(case_dir / "case.sqlite") as store:
        assert store.count() == 0
    assert (case_dir / "report" / "report.json").exists()


def test_inputs_hashed_before_parsing_and_never_modified(tmp_path: Path):
    inp = tmp_path / "in"
    (inp / "sub").mkdir(parents=True)
    a = inp / "a.txt"
    a.write_bytes(b"not a log\n")
    b = inp / "sub" / "b.bin"
    b.write_bytes(bytes(range(256)))
    before = {p: (sha256_file(p), p.stat().st_mtime_ns) for p in (a, b)}
    case_dir = tmp_path / "case"
    assert main(["-q", "ingest", str(inp), "--case", str(case_dir)]) == 0
    manifest = json.loads((case_dir / "manifest.json").read_text(encoding="utf-8"))
    paths = [i["path"] for i in manifest["inputs"]]
    assert paths == ["a.txt", "sub/b.bin"]
    for p, (h, mt) in before.items():
        assert sha256_file(p) == h
        assert p.stat().st_mtime_ns == mt
    hashes = {i["path"]: i["sha256"] for i in manifest["inputs"]}
    assert hashes["a.txt"] == before[a][0]
    assert manifest["totals"]["files_unrecognised"] == 2


def test_case_folder_not_overwritten_without_force(tmp_path: Path):
    inp = tmp_path / "in"
    inp.mkdir()
    case_dir = tmp_path / "case"
    assert main(["-q", "ingest", str(inp), "--case", str(case_dir)]) == 0
    assert main(["-q", "ingest", str(inp), "--case", str(case_dir)]) == 2
    assert main(["-q", "ingest", str(inp), "--case", str(case_dir), "--force"]) == 0


def test_force_refuses_foreign_files(tmp_path: Path):
    inp = tmp_path / "in"
    inp.mkdir()
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "precious.docx").write_text("x")
    assert main(["-q", "ingest", str(inp), "--case", str(case_dir), "--force"]) == 2
    assert (case_dir / "precious.docx").exists()


def test_case_inside_input_rejected(tmp_path: Path):
    inp = tmp_path / "in"
    inp.mkdir()
    assert main(["-q", "ingest", str(inp), "--case", str(inp / "case")]) == 2


def test_netguard_blocks_sockets_in_cli_process():
    code = (
        "import socket, sys\n"
        "from tenanttrace import netguard\n"
        "netguard.install()\n"
        "try:\n"
        "    socket.create_connection(('192.0.2.1', 80), timeout=1)\n"
        "except netguard.NetworkBlocked:\n"
        "    sys.exit(0)\n"
        "sys.exit(3)\n"
    )
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
