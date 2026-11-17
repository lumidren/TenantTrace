"""Parser and normalization tests: every corpus layout, malformed input, raw pointers, linking."""

from __future__ import annotations

import json
import shutil
from collections import defaultdict
from pathlib import Path

import pytest

from tenanttrace.case import Case
from tenanttrace.hashing import sha256_text
from tenanttrace.ingest.readers import detect_encoding, read_head, read_spans
from tenanttrace.ingest.ual import normalize_auditdata, split_ip
from tenanttrace.pipeline import ingest
from tenanttrace.store import CaseStore

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PARSER = {
    "purview_ual_csv": "purview_ual_csv",
    "purview_ual_csv_v2": "purview_ual_csv",
    "ps_ual_csv": "ps_ual_csv",
    "entra_signin_csv": "entra_signin_csv",
    "entra_signin_json": "entra_signin_json",
    "extractor_suite_ual_json": "ual_json",
    "extractor_suite_signin_json": "entra_signin_json",
    "hawk_raw_json": "ual_json",
    "hawk_flat_csv": "ual_flat_csv",
}


def _ingest(src: Path, tmp_path: Path, name: str = "case"):
    case = Case(tmp_path / name)
    manifest = ingest(src, case, force=True)
    return case, manifest


@pytest.fixture(scope="module")
def ingested(corpus_dir, tmp_path_factory):
    out = {}
    base = tmp_path_factory.mktemp("cases")
    for sid in ("demo_bec", "attack_legacy_forwarding", "attack_oauth_consent", "benign_admin_bulk",
                "benign_travel_newphone", "collector_hawk_legacy"):
        case = Case(base / sid)
        out[sid] = (case, ingest(corpus_dir / sid / "exports", case, force=True))
    return out


def test_every_layout_gets_the_right_parser_and_all_records(ingested, corpus_dir):
    seen = set()
    for sid, (case, manifest) in ingested.items():
        gt = json.loads((corpus_dir / sid / "ground_truth.json").read_text(encoding="utf-8"))
        by_path = {i["path"]: i for i in manifest["inputs"]}
        for f in gt["files"]:
            entry = by_path[f["path"]]
            assert entry["parser"] == EXPECTED_PARSER[f["format"]], (sid, f["path"], entry["parser_reason"])
            assert entry["records_parsed"] == f["records"], (sid, f["path"])
            assert entry["records_unrecognised"] == 0 and entry["records_malformed"] == 0
            seen.add(f["format"])
    assert seen == set(EXPECTED_PARSER)


def test_counts_reconcile_with_inputs(ingested):
    for sid, (case, manifest) in ingested.items():
        with CaseStore(case.db_path) as store:
            per_file = dict(store.conn.execute("SELECT file_id, COUNT(*) FROM events GROUP BY file_id").fetchall())
            files = store.files()
        for f in files:
            assert f["records_total"] == f["records_parsed"] + f["records_unrecognised"] + f["records_malformed"]
            assert per_file.get(f["file_id"], 0) == f["records_parsed"], (sid, f["rel_path"])
        t = manifest["totals"]
        assert t["records_total"] == t["records_parsed"] + t["records_unrecognised"] + t["records_malformed"]


def test_every_event_resolves_to_its_exact_source_record(ingested):
    case, manifest = ingested["demo_bec"]
    root = Path(manifest["input_dir"])
    checked = 0
    with CaseStore(case.db_path) as store:
        files = {f["file_id"]: f for f in store.files()}
        spans = defaultdict(list)
        for row in store.conn.execute(
                "SELECT event_id, file_id, line_start, col_start, line_end, col_end, raw_sha256, record_id, source "
                "FROM events"):
            spans[row[1]].append(row)
    for fid, rows in spans.items():
        path = root / files[fid]["rel_path"]
        enc = detect_encoding(read_head(path))
        texts = read_spans(path, enc, [(r[2], r[3], r[4], r[5]) for r in rows])
        for r in rows:
            raw = texts[(r[2], r[3], r[4], r[5])]
            assert sha256_text(raw) == r[6], r[0]
            # the raw record really is the record the event claims to come from
            if path.suffix == ".json":
                assert json.loads(raw)["id"] == r[7]
            else:
                assert r[7] in raw
            checked += 1
    assert checked == manifest["totals"]["records_parsed"]


def test_combined_signin_file_is_split_by_record(ingested):
    case, manifest = ingested["attack_oauth_consent"]
    entry = next(i for i in manifest["inputs"] if "SignInLogs.json" in i["path"])
    by_src = entry["info"]["events_by_source"]
    assert by_src["entra_signin_interactive"] > 0 and by_src["entra_signin_noninteractive"] > 0


def test_ual_signin_copies_corroborate_entra_records(ingested):
    case, manifest = ingested["demo_bec"]
    with CaseStore(case.db_path) as store:
        ual_logons = store.count("source='ual_azuread_logon'")
        corr = store.count("link_role='corroborating'")
        primaries = store.count("link_role='primary' AND source LIKE 'entra_signin%'")
        basis = store.conn.execute("SELECT link_basis FROM events WHERE link_role='corroborating' LIMIT 1").fetchone()[0]
    assert ual_logons == corr == primaries == manifest["linking"]["corroborating"] > 0
    assert "same account, IP address and outcome" in basis


def test_overlapping_exports_are_linked_as_duplicates(corpus_dir, tmp_path):
    src = tmp_path / "in"
    shutil.copytree(corpus_dir / "benign_travel_newphone" / "exports", src)
    shutil.copy(src / "AuditLog_maya.csv", src / "AuditLog_maya_again.csv")
    case, manifest = _ingest(src, tmp_path)
    ual_rows = next(i for i in manifest["inputs"] if i["path"] == "AuditLog_maya.csv")["records_parsed"]
    assert manifest["linking"]["duplicates"] == ual_rows
    with CaseStore(case.db_path) as store:
        assert store.count("link_role='duplicate'") == ual_rows


def test_third_party_samples_parse_without_loss(tmp_path):
    case, manifest = _ingest(ROOT / "samples" / "third_party", tmp_path)
    logs = [i for i in manifest["inputs"] if i["path"].endswith(".log")]
    assert len(logs) == 4
    for i in logs:
        assert i["parser"] in ("ual_json", "entra_signin_azure_monitor")
        assert i["records_parsed"] == i["records_total"] > 0
    others = [i for i in manifest["inputs"] if not i["path"].endswith(".log")]
    assert all(i["parser"] is None for i in others)
    with CaseStore(case.db_path) as store:
        ops = {r[0] for r in store.conn.execute("SELECT DISTINCT lower(operation) FROM events")}
        assert {"new-inboxrule", "set-inboxrule"} <= ops


# ----------------------------------------------------------------------------- hostile input

CSV_HEADER = '"CreationDate","UserIds","Operations","AuditData"\r\n'


def _row(ad: dict) -> str:
    j = json.dumps(ad).replace('"', '""')
    return f'"{ad.get("CreationTime", "")}","{ad.get("UserId", "")}","{ad.get("Operation", "")}","{j}"\r\n'


def _ad(i: int, **kw) -> dict:
    d = {"CreationTime": f"2026-10-25T0{i % 10}:30:00", "Id": f"00000000-0000-4000-8000-{i:012d}",
         "Operation": "FileAccessed", "RecordType": 6, "Workload": "SharePoint", "UserId": "a.user@contoso.example",
         "UserKey": "k", "UserType": 0, "OrganizationId": "o", "ClientIP": "192.0.2.5", "ResultStatus": "Succeeded"}
    d.update(kw)
    return d


def test_malformed_rows_are_counted_never_dropped(tmp_path):
    src = tmp_path / "in"
    src.mkdir()
    good = [_row(_ad(i)) for i in range(5)]
    bad_json = '"2026-10-25T01:00:00","a.user@contoso.example","FileAccessed","{not json"\r\n'
    no_op = _row({k: v for k, v in _ad(7).items() if k != "Operation"})
    bad_time = _row(_ad(8, CreationTime="yesterday at noon"))
    short_row = '"2026-10-25T02:00:00","a.user@contoso.example"\r\n'
    (src / "ual.csv").write_text(CSV_HEADER + "".join(good) + bad_json + no_op + bad_time + short_row,
                                 encoding="utf-8", newline="")
    case, manifest = _ingest(src, tmp_path)
    f = manifest["inputs"][0]
    assert f["parser"] == "purview_ual_csv"
    assert f["records_parsed"] == 5
    assert f["records_malformed"] == 2      # bad JSON, short row
    assert f["records_unrecognised"] == 2   # no Operation, bad timestamp
    assert f["records_total"] == 9
    with CaseStore(case.db_path) as store:
        reasons = [r[0] for r in store.conn.execute("SELECT reason FROM unrecognised ORDER BY line_start")]
    assert any("not valid JSON" in r for r in reasons)
    assert any("no Operation" in r for r in reasons)
    assert any("timestamp" in r for r in reasons)
    assert any("fields" in r for r in reasons)


def test_truncated_json_export(tmp_path):
    src = tmp_path / "in"
    src.mkdir()
    recs = [json.dumps({"createdDateTime": f"2026-10-0{i + 1}T10:00:00Z", "id": f"r{i}",
                        "userPrincipalName": "a.user@contoso.example", "ipAddress": "192.0.2.1",
                        "status": {"errorCode": 0}}) for i in range(4)]
    text = "[\n" + ",\n".join(recs) + ',\n{"createdDateTime": "2026-10-09T10:00:00Z", "id": "r9", "userPrin'
    (src / "signins.json").write_text(text, encoding="utf-8")
    case, manifest = _ingest(src, tmp_path)
    f = manifest["inputs"][0]
    assert f["parser"] == "entra_signin_json"
    assert (f["records_parsed"], f["records_malformed"]) == (4, 1)


def test_empty_binary_and_unknown_files(tmp_path):
    src = tmp_path / "in"
    src.mkdir()
    (src / "empty.csv").write_bytes(b"")
    (src / "image.bin").write_bytes(bytes(range(256)) * 20)
    (src / "notes.txt").write_text("collected by the client's IT team\n", encoding="utf-8")
    (src / "other.csv").write_text("a,b,c\n1,2,3\n", encoding="utf-8")
    case, manifest = _ingest(src, tmp_path)
    by = {i["path"]: i for i in manifest["inputs"]}
    assert by["empty.csv"]["parser_reason"] == "empty file"
    for name in ("image.bin", "notes.txt", "other.csv"):
        assert by[name]["parser"] is None and "no parser recognised" in by[name]["parser_reason"]
    assert manifest["totals"]["files_unrecognised"] == 4


@pytest.mark.parametrize("encoding,bom", [("utf-16-le", b""), ("utf-16-le", b"\xff\xfe"), ("cp1252", b"")])
def test_wrong_or_unusual_encodings(tmp_path, encoding, bom):
    src = tmp_path / "in"
    src.mkdir()
    rows = "".join(_row(_ad(i, UserId="josé.müller@contoso.example")) for i in range(3))
    (src / "ual.csv").write_bytes(bom + (CSV_HEADER + rows).encode(encoding))
    case, manifest = _ingest(src, tmp_path)
    f = manifest["inputs"][0]
    assert f["parser"] == "purview_ual_csv" and f["records_parsed"] == 3
    with CaseStore(case.db_path) as store:
        assert store.count("actor = ?", ("josé.müller@contoso.example",)) == 3


# ----------------------------------------------------------------------------- normalization


def test_inbox_rule_parameters():
    ad = _ad(1, Operation="New-InboxRule", RecordType=1, Workload="Exchange", ClientIP="203.0.113.9:51234",
             ObjectId="A User\\..", Parameters=[
                 {"Name": "Name", "Value": ".."},
                 {"Name": "SubjectOrBodyContainsWords", "Value": "invoice;payment, bank"},
                 {"Name": "MoveToFolder", "Value": "RSS Subscriptions"},
                 {"Name": "MarkAsRead", "Value": "True"},
                 {"Name": "ForwardTo", "Value": "smtp:x@elsewhere.example.net"}])
    ev = normalize_auditdata(ad)
    assert (ev.category, ev.action, ev.source) == ("mail_rule", "inbox_rule.create", "ual_exchange_admin")
    assert ev.ip == "203.0.113.9" and ev.details["ip_raw"] == "203.0.113.9:51234"
    d = ev.details
    assert d["rule_name"] == ".." and d["keywords"] == ["invoice", "payment", "bank"]
    assert d["move_to_folder"] == "RSS Subscriptions" and d["mark_as_read"] is True
    assert d["forward_to"] == "x@elsewhere.example.net"


def test_mailbox_forwarding_and_folder_permission():
    fwd = normalize_auditdata(_ad(2, Operation="Set-Mailbox", RecordType=1, Parameters=[
        {"Name": "Identity", "Value": "b.user@contoso.example"},
        {"Name": "ForwardingSmtpAddress", "Value": "smtp:copy@relay.example.net"},
        {"Name": "DeliverToMailboxAndForward", "Value": "True"}]))
    assert fwd.action == "mailbox.forwarding_set" and fwd.details["forward_to"] == "copy@relay.example.net"
    assert fwd.target == "b.user@contoso.example" and fwd.details["deliver_and_forward"] is True
    perm = normalize_auditdata(_ad(3, Operation="Add-MailboxFolderPermission", RecordType=1, Parameters=[
        {"Name": "Identity", "Value": "c.user@contoso.example:\\Inbox"},
        {"Name": "User", "Value": "Default"}, {"Name": "AccessRights", "Value": "Reviewer"}]))
    assert perm.action == "mailbox.folder_permission_add" and perm.target == "c.user@contoso.example"
    assert perm.details["grantee"] == "Default" and perm.details["folder"] == "\\Inbox"


def test_consent_scopes_and_app_id():
    ad = _ad(4, Operation="Consent to application.", RecordType=8, Workload="AzureActiveDirectory",
             Target=[{"ID": "Some Viewer", "Type": 1}], ModifiedProperties=[
                 {"Name": "ConsentContext.IsAdminConsent", "NewValue": "False", "OldValue": ""},
                 {"Name": "ConsentAction.Permissions", "NewValue":
                     "[] => [[Id: x, ClientId: y, ConsentType: Principal, Scope: Mail.ReadWrite offline_access, "
                     "CreatedDateTime: ]]; ", "OldValue": ""},
                 {"Name": "TargetId.ServicePrincipalNames", "NewValue": "7D1C3A90-4B2E-4F6A-9C11-5E2A8B7F0D42"}])
    ev = normalize_auditdata(ad)
    assert ev.action == "app.consent" and ev.details["scopes"] == ["Mail.ReadWrite", "offline_access"]
    assert ev.app_id == "7d1c3a90-4b2e-4f6a-9c11-5e2a8b7f0d42" and ev.details["app_name"] == "Some Viewer"
    assert ev.details["is_admin_consent"] is False


def test_sts_logon_outcome_comes_from_error_code_not_result_status():
    base = dict(Operation="UserLoginFailed", RecordType=15, Workload="AzureActiveDirectory", ResultStatus="Success", ClientIP=None,
                ActorIpAddress="198.51.100.7", ExtendedProperties=[{"Name": "UserAgent", "Value": "ua"}])
    assert normalize_auditdata(_ad(5, ErrorNumber="50126", **base)).outcome == "failure"
    ok = normalize_auditdata(_ad(6, ErrorCode="0", **{**base, "Operation": "UserLoggedIn"}))
    assert ok.outcome == "success" and ok.ip == "198.51.100.7" and ok.user_agent == "ua"


@pytest.mark.parametrize("raw,ip", [("203.0.113.5:443", "203.0.113.5"), ("[2001:db8::1]:8443", "2001:db8::1"),
                                    ("2001:db8::7", "2001:db8::7"), ("192.0.2.1", "192.0.2.1"), ("", "")])
def test_split_ip(raw, ip):
    assert split_ip(raw) == ip


def test_record_type_by_name_and_operation_case():
    ev = normalize_auditdata(_ad(9, RecordType="ExchangeAdmin", Operation="set-InboxRule", Parameters=[]))
    assert ev.source == "ual_exchange_admin" and ev.action == "inbox_rule.update"


def test_flattened_rows_rebuild_into_audit_records():
    from tenanttrace.ingest.parsers import rebuild_auditdata

    header = ["CreationTime", "Workload", "RecordType", "Operation", "ResultStatus", "ClientIP", "UserId", "Id",
              "AppAccessContext", "ParameterString", "Param_ForwardingSmtpAddress", "Param_Identity", "CountryName"]
    row = ["2026-09-29T04:21:00", "Exchange", "1", "Set-Mailbox", "True", "203.0.113.120:1234",
           "a@contoso.example", "11111111-1111-4111-8111-111111111111",
           "@{AADSessionId=s-1; UniqueTokenId=TokA}", "-Identity a@contoso.example",
           "smtp:x@relay.example.net", "a@contoso.example", "Germany"]
    ad, enrichment = rebuild_auditdata(header, row)
    assert ad["RecordType"] == 1 and ad["AppAccessContext"] == {"AADSessionId": "s-1", "UniqueTokenId": "TokA"}
    assert {"Name": "ForwardingSmtpAddress", "Value": "smtp:x@relay.example.net"} in ad["Parameters"]
    assert enrichment == {"CountryName": "Germany"}       # collector enrichment is kept apart
    ev = normalize_auditdata(ad)
    assert ev.action == "mailbox.forwarding_set" and ev.session_id == "s-1" and ev.token_id == "TokA"
    assert ev.geo_country == ""                            # location never comes from collector enrichment
