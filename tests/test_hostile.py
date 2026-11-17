"""Awkward input end to end: timestamps across a daylight-saving change, and an account that appears
in no log at all."""

from __future__ import annotations

import json

from tenanttrace.case import Case
from tenanttrace.pipeline import ingest, run_all
from tenanttrace.store import CaseStore


def test_signins_with_local_offsets_across_the_uk_clock_change(tmp_path):
    # Clocks went back at 01:00 UTC on 2026-10-25: 01:30+01:00 comes before 01:30+00:00.
    stamps = ["2026-10-25T00:30:00+01:00", "2026-10-25T01:30:00+01:00", "2026-10-25T01:30:00+00:00",
              "2026-10-25T02:30:00+00:00"]
    recs = [{"id": f"r{i}", "createdDateTime": t, "userPrincipalName": "a.user@contoso.example",
             "ipAddress": "192.0.2.1", "status": {"errorCode": 0}, "isInteractive": True}
            for i, t in enumerate(reversed(stamps))]          # written out of order on purpose
    src = tmp_path / "in"
    src.mkdir()
    (src / "signins.json").write_text(json.dumps(recs), encoding="utf-8")
    case = Case(tmp_path / "case")
    ingest(src, case, force=True)
    with CaseStore(case.db_path) as store:
        rows = store.conn.execute("SELECT ts_utc, ts_original, ts_note FROM events ORDER BY ts_utc").fetchall()
    assert [r[0][:16] for r in rows] == ["2026-10-24T23:30", "2026-10-25T00:30", "2026-10-25T01:30", "2026-10-25T02:30"]
    assert [r[1] for r in rows] == stamps                     # the original value is kept verbatim
    assert all("offset" in r[2] or "zone" in r[2] for r in rows)


def test_account_absent_from_every_log(corpus_dir, tmp_path):
    case = Case(tmp_path / "case")
    out = run_all(corpus_dir / "demo_bec" / "exports", case, user="nobody@harborlane.example",
                  collected_at="2026-11-06T17:00:00Z", pdf=True)
    assert out["analysis"]["summary"]["findings"] == 0
    kinds = {(g["kind"], g["source"]) for g in out["coverage"]["gaps"]}
    assert ("user_absent", "entra_signin_interactive") in kinds
    data = json.loads((case.report_dir / "report.json").read_text(encoding="utf-8"))
    assert "No findings" in data["summary"]["headline"]
    assert any("not for nobody@harborlane.example" in lim for lim in data["summary"]["limits"])
