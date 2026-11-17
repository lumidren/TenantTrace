"""Evidence gap analysis on the corpus: degraded cases report the right gap and cause; intact
cases report none (beyond what their ground truth expects)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

from tenanttrace.case import Case
from tenanttrace.coverage.reference import load_reference
from tenanttrace.pipeline import coverage, ingest

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ["demo_bec", "attack_legacy_forwarding", "attack_oauth_consent", "attack_travel_delegate",
             "benign_admin_bulk", "benign_forwarding_vpn", "benign_travel_newphone", "degraded_no_signins",
             "degraded_ual_truncated", "degraded_retention_7d", "degraded_no_mailbox_audit", "degraded_quiet_period"]


@pytest.fixture(scope="module")
def covered(corpus_dir, tmp_path_factory):
    base = tmp_path_factory.mktemp("cov")
    out = {}
    for sid in SCENARIOS:
        gt = json.loads((corpus_dir / sid / "ground_truth.json").read_text(encoding="utf-8"))
        case = Case(base / sid)
        ingest(corpus_dir / sid / "exports", case, force=True)
        out[sid] = (gt, coverage(case, user=gt["primary_user"], collected_at=gt["collected_at"]))
    return out


def _matches(gap: dict, want: dict) -> bool:
    if gap["kind"] != want["kind"]:
        return False
    if gap["source"] != want["source"] and want["source"] not in (gap.get("affects_sources") or []):
        return False
    if want.get("cause_contains"):
        text = gap["statement"] + " " + " ".join(gap["likely_causes"])
        return want["cause_contains"] in text
    return True


@pytest.mark.parametrize("sid", SCENARIOS)
def test_gaps_match_ground_truth(covered, sid):
    gt, cov = covered[sid]
    gaps = cov["gaps"]
    for want in gt["expected_gaps"]:
        assert any(_matches(g, want) for g in gaps), (sid, want, [(g["kind"], g["source"]) for g in gaps])
    unexpected = [g for g in gaps if not any(_matches(g, w) for w in gt["expected_gaps"])]
    assert not unexpected, (sid, [(g["kind"], g["source"], g["statement"]) for g in unexpected])


def test_intact_cases_report_no_gaps(covered):
    for sid in ("attack_legacy_forwarding", "attack_oauth_consent", "attack_travel_delegate", "benign_admin_bulk",
                "benign_forwarding_vpn", "benign_travel_newphone"):
        assert covered[sid][1]["gaps"] == [], sid


def test_retention_cause_names_the_licence(covered):
    gaps = covered["degraded_retention_7d"][1]["gaps"]
    for g in gaps:
        assert g["kind"] == "retention" and g["retention_days"] == 7
        assert "Microsoft Entra ID Free" in g["licence_hint"]
        assert g["citations"] and all(c["url"].startswith("https://learn.microsoft.com/") for c in g["citations"])


def test_auditing_absent_lists_documented_causes(covered):
    g = next(g for g in covered["degraded_no_mailbox_audit"][1]["gaps"] if g["kind"] == "auditing_absent")
    text = " ".join(g["likely_causes"])
    assert "AuditDisabled" in text and "bypass" in text and "E3/E5" in text


def test_truncation_evidence_is_quoted(covered):
    g = next(g for g in covered["degraded_ual_truncated"][1]["gaps"] if g["kind"] == "truncated")
    assert re.search(r"ResultCount reports [\d,]+ results but the file holds [\d,]+ rows", g["statement"])


def test_sparse_sources_without_records_are_not_gaps(covered):
    # the legacy-protocol case has no Entra directory changes at all: absence is normal for sparse sources
    cov = covered["attack_legacy_forwarding"][1]
    row = next(s for s in cov["sources"] if s["source"] == "ual_azuread")
    assert row["status"] == "no_records" and row["activity"] == "sparse"


def test_user_who_appears_in_no_log(corpus_dir, tmp_path):
    case = Case(tmp_path / "case")
    ingest(corpus_dir / "benign_forwarding_vpn" / "exports", case, force=True)
    cov = coverage(case, user="nobody.here@alderfinch.example", collected_at="2026-10-23T17:00:00Z")
    assert cov["summary"]["user_events"] == 0
    kinds = {(g["kind"], g["source"]) for g in cov["gaps"]}
    assert ("user_absent", "entra_signin_interactive") in kinds
    assert ("user_absent", "ual_mailbox_items") in kinds


def test_reference_table_is_complete_and_cited():
    ref = load_reference()
    assert re.match(r"\d{4}\.\d{2}\.\d{2}", ref.version)
    verify_md = (ROOT / "docs" / "VERIFY.md").read_text(encoding="utf-8")
    for e in ref.sources:
        assert e["citations"], e["id"]
        for c in e["citations"]:
            assert c["url"].startswith("https://learn.microsoft.com/"), c
        assert e["last_checked"] == "2026-11-17"
        if not e["verified"]:
            assert e.get("unverified"), e["id"]
            assert f"`{e['id']}`" in verify_md, e["id"]
    raw = yaml.safe_load((ROOT / "src" / "tenanttrace" / "reference" / "gap_reference.yaml").read_text(encoding="utf-8"))
    assert raw["version"] == ref.version
