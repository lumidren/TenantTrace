"""The optional offline IP database fills only what the logs leave empty, and says so."""

from __future__ import annotations

import json

from tenanttrace.case import Case
from tenanttrace.pipeline import analyze, coverage, ingest, report
from tenanttrace.store import CaseStore


def test_ipdb_fills_missing_coordinates_and_enables_impossible_travel(corpus_dir, tmp_path):
    # the legacy-protocol case ships Entra CSV sign-ins: countries but no coordinates
    gt = json.loads((corpus_dir / "attack_legacy_forwarding" / "ground_truth.json").read_text(encoding="utf-8"))
    ipdb = tmp_path / "my-ip-locations.csv"
    ipdb.write_text(
        "network,country,city,latitude,longitude\n"
        "192.0.2.0/24,GB,Manchester,53.4808,-2.2426\n"
        "198.51.100.0/24,GB,Manchester,53.4808,-2.2426\n"
        "203.0.113.0/24,DE,Frankfurt am Main,50.1109,8.6821\n"
        "2001:db8::/32,GB,Manchester,53.4808,-2.2426\n", encoding="utf-8")
    case = Case(tmp_path / "case")
    ingest(corpus_dir / "attack_legacy_forwarding" / "exports", case, force=True)
    coverage(case, user=gt["primary_user"], collected_at=gt["collected_at"])
    before = {c["rule_id"]: c["status"] for c in analyze(case)["capability"]}
    assert before["TT-SIGNIN-002"] == "not_assessable"          # CSV download has no coordinates
    res = analyze(case, ipdb=str(ipdb))
    after = {c["rule_id"]: c["status"] for c in res["capability"]}
    assert after["TT-SIGNIN-002"] != "not_assessable"
    assert res["ipdb"]["events_enriched"] > 0 and len(res["ipdb"]["sha256"]) == 64
    with CaseStore(case.db_path) as store:
        # a country the log recorded is kept; only the coordinates come from the database
        row = store.conn.execute("SELECT geo_country, geo_source FROM events WHERE source='entra_signin_interactive' "
                                 "AND geo_lat IS NOT NULL LIMIT 1").fetchone()
        assert row[0] == "GB" and row[1] == "log+ipdb:my-ip-locations.csv"
    report(case, pdf=False)
    data = json.loads((case.report_dir / "report.json").read_text(encoding="utf-8"))
    assert any("offline IP database my-ip-locations.csv" in lim for lim in data["summary"]["limits"])
