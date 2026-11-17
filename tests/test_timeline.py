"""Timeline order and labels, session linking and the tenant pivot."""

from __future__ import annotations

import csv
import io
import json
import shutil
from pathlib import Path

import pytest

from tenanttrace.case import Case
from tenanttrace.pipeline import analyze, coverage, ingest


def _analyse(src: Path, tmp: Path, gt: dict) -> dict:
    case = Case(tmp)
    ingest(src, case, force=True)
    coverage(case, user=gt["primary_user"], collected_at=gt["collected_at"], window_start=gt.get("window_start"))
    return analyze(case)


@pytest.fixture(scope="module")
def results(corpus_dir, tmp_path_factory):
    out = {}
    base = tmp_path_factory.mktemp("tl")
    for sid in ("demo_bec", "attack_legacy_forwarding", "attack_oauth_consent"):
        gt = json.loads((corpus_dir / sid / "ground_truth.json").read_text(encoding="utf-8"))
        out[sid] = (gt, _analyse(corpus_dir / sid / "exports", base / sid, gt))
    return out


def test_demo_timeline_reads_in_order(results):
    gt, res = results["demo_bec"]
    steps = res["timeline"]["steps"]
    assert [s["seq"] for s in steps] == list(range(1, len(steps) + 1))
    assert [s["ts"] for s in steps] == sorted(s["ts"] for s in steps)

    def first(rule: str) -> str:
        return min(s["ts"] for s in steps if s.get("rule_id") == rule and s["kind"] == "finding")

    story = ["TT-SIGNIN-001", "TT-AUTH-001", "TT-MAIL-001", "TT-MAIL-004", "TT-FILE-001", "TT-FILE-002"]
    times = [first(r) for r in story]
    assert times == sorted(times) and len(set(times)) == len(times)
    start = next(s for s in steps if s["title"].startswith("Likely start of attacker access"))
    assert start["ts"].startswith(gt["compromise_start"][:16])   # the attacker's sign-in, not the user's own


def test_every_step_is_labelled_and_inferences_state_their_basis(results):
    for sid, (_, res) in results.items():
        for s in res["timeline"]["steps"]:
            assert s["label"] in ("observed", "inference"), (sid, s)
            if s["label"] == "inference":
                assert s.get("basis") or s.get("session_link", {}).get("text"), (sid, s["title"])
            if s["kind"] == "finding":
                assert s["level"] in ("confirmed", "probable", "possible") and s["level_reason"], s
            assert s["event_ids"], (sid, s["title"])


def test_replayed_session_is_an_inference_with_basis(results):
    _, res = results["demo_bec"]
    rep = [s for s in res["timeline"]["steps"] if "same sign-in session was used" in s["title"]]
    assert len(rep) == 1
    assert rep[0]["label"] == "inference" and any("session ID" in b for b in rep[0]["basis"])


def test_post_compromise_steps_link_by_recorded_identifier(results):
    _, res = results["demo_bec"]
    for s in res["timeline"]["steps"]:
        if s["kind"] == "finding" and s.get("rule_id") in ("TT-MAIL-001", "TT-AUTH-001", "TT-FILE-001"):
            assert s["session_link"]["method"] in ("token_id", "session_id")
            assert s["session_link"]["label"] == "observed"
    assert res["timeline"]["linking"].get("token_id", 0) + res["timeline"]["linking"].get("session_id", 0) > 0


def test_link_without_session_identifiers_is_marked_as_inference(corpus_dir, tmp_path):
    """Strip AppAccessContext from the demo's audit records: links must fall back to IP and time,
    and be labelled as inferences."""
    src = tmp_path / "in"
    shutil.copytree(corpus_dir / "demo_bec" / "exports", src)
    path = next(src.rglob("*.csv"))
    raw = path.read_bytes()
    text = raw[3:].decode("utf-8")
    rows = list(csv.reader(io.StringIO(text)))
    for r in rows[1:]:
        ad = json.loads(r[3])
        ad.pop("AppAccessContext", None)
        r[3] = json.dumps(ad)
    buf = io.StringIO()
    csv.writer(buf, quoting=csv.QUOTE_ALL, lineterminator="\r\n").writerows(rows)
    path.write_bytes(b"\xef\xbb\xbf" + buf.getvalue().encode("utf-8"))
    gt = json.loads((corpus_dir / "demo_bec" / "ground_truth.json").read_text(encoding="utf-8"))
    res = _analyse(src, tmp_path / "case", gt)
    rule_step = next(s for s in res["timeline"]["steps"] if s.get("rule_id") == "TT-MAIL-001" and s["kind"] == "finding")
    assert rule_step["session_link"]["method"] == "ip_time"
    assert rule_step["session_link"]["label"] == "inference"
    attribution = [s for s in res["timeline"]["steps"] if s["kind"] == "attribution"]
    assert attribution and all(s["label"] == "inference" and s["basis"] for s in attribution)
    # without the shared session, the hiding rule can no longer be confirmed by session
    f = next(f for f in res["findings"] if f["rule_id"] == "TT-MAIL-001")
    assert f["level"] == "probable"


def test_pivot_lists_the_second_victim(results):
    gt, res = results["demo_bec"]
    accounts = [p["account"] for p in res["pivot"]]
    assert accounts == gt["expected_pivot"]
    m = res["pivot"][0]["matches"][0]
    assert m["kind"] == "ip" and m["value"] == "203.0.113.45" and m["example_event_ids"]


def test_pivot_finds_spray_targets_and_consenting_users(results):
    gt, res = results["attack_legacy_forwarding"]
    assert sorted(p["account"] for p in res["pivot"]) == sorted(gt["expected_pivot"])
    for p in res["pivot"]:
        assert any("signin:failure" in m["actions"] for m in p["matches"])
    gt, res = results["attack_oauth_consent"]
    assert [p["account"] for p in res["pivot"]] == gt["expected_pivot"]
    assert any(m["kind"] == "app_id" for m in res["pivot"][0]["matches"])
