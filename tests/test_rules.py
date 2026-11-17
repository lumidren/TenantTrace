"""Rule engine and rule set tests: every rule has a positive and a negative case."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tenanttrace.analysis import rule_capability
from tenanttrace.rules.baseline import build_baseline
from tenanttrace.rules.engine import LEVELS, Context, Engine, load_rules
from tenanttrace.schema import Event

ROOT = Path(__file__).resolve().parents[1]
USER = "victim@contoso.example"
WINDOW = "2026-10-20T00:00:00.000000Z"
_n = [0]


def ev(ts: str, **kw) -> Event:
    _n[0] += 1
    base = dict(event_id=f"E{_n[0]:06d}", ts_utc=ts, actor=USER, target=USER, outcome="success")
    base.update(kw)
    return Event(**base)


def signin(ts: str, ip="192.0.2.10", country="GB", lat=53.8, lon=-1.55, **kw) -> Event:
    d = dict(source="entra_signin_interactive", category="signin", action="signin", ip=ip, geo_country=country,
             geo_lat=lat, geo_lon=lon, device_os="Windows10", device_browser="Edge 128.0.0",
             user_agent="Mozilla/5.0 (Windows NT 10.0) Chrome/128.0 Safari/537.36 Edg/128.0", interactive=1,
             client_app="Browser", auth_requirement="multiFactorAuthentication", session_id="S-base")
    d.update(kw)
    return ev(ts, **d)


def history() -> list[Event]:
    """Twenty working days of ordinary activity before the window."""
    out = []
    for day in range(1, 20):
        ts = f"2026-10-{day:02d}T08:30:00.000000Z"
        out.append(signin(ts))
        out.append(ev(f"2026-10-{day:02d}T09:00:00.000000Z", source="ual_sharepoint", category="file_access",
                      action="file.downloaded", ip="192.0.2.10", user_agent=out[-1].user_agent,
                      session_id="S-base"))
        out.append(ev(f"2026-10-{day:02d}T10:00:00.000000Z", source="ual_mailbox_items", category="mail_access",
                      action="mail.items_accessed", ip="192.0.2.10", client_app="OWA", session_id="S-base",
                      details={"access_type": "Bind", "item_count": 1}))
    return out


def run(rule_id: str, events: list[Event], flagged_ips=(), flagged_sessions=(), failed_users=None):
    _, rules = load_rules()
    rule = next(r for r in rules if r.id == rule_id)
    from tenanttrace.analysis import _session_countries

    b = build_baseline(events, WINDOW)
    ctx = Context(user=USER, window_start=WINDOW, baseline=b, tenant_domains={"contoso.example"},
                  session_countries=_session_countries(events), ip_failed_users=failed_users or {})
    ctx.flagged_ips.update(flagged_ips)
    ctx.suspect_ips.update(flagged_ips)
    ctx.flagged_sessions.update(flagged_sessions)
    return Engine(rules, ctx, events).run_rule(rule)


def test_rule_set_is_well_formed():
    version, rules = load_rules()
    assert version and len(rules) >= 18
    attack_doc = (ROOT / "docs" / "sources" / "attack-techniques.md").read_text(encoding="utf-8")
    confirmed_ids = set(re.findall(r"\|\s*(T\d{4}(?:\.\d{3})?)\s*\|", attack_doc))
    for r in rules:
        d = r.data
        assert d["why"].strip() and d["benign"], r.id
        assert d["kind"] in ("match", "threshold", "deviation", "sequence", "travel")
        levels = [c["level"] for c in d["confidence"]]
        assert levels == [lv for lv in LEVELS if lv in levels], (r.id, "levels out of order")
        assert d["confidence"][-1]["when"] is True, (r.id, "last level must be the fallback")
        assert all(c["reason"] for c in d["confidence"])
        for t in d["attack"]:
            assert t["id"] in confirmed_ids, (r.id, t["id"], "ATT&CK id not in the confirmed list")
        assert d["sources"], r.id
        assert "score" not in d and "risk" not in d, "no numeric scores anywhere"


# --- sign-in rules ---------------------------------------------------------------


def test_unfamiliar_country():
    h = history()
    pos = run("TT-SIGNIN-001", h + [signin("2026-10-21T10:00:00.000000Z", ip="203.0.113.9", country="US",
                                           device_os="Linux", device_browser="Chrome 126.0.0", session_id="S-x")])
    assert len(pos) == 1 and pos[0].level == "probable"
    neg = run("TT-SIGNIN-001", h + [signin("2026-10-21T10:00:00.000000Z")])
    assert neg == []


def test_impossible_travel_and_replayed_session():
    h = history()
    a = signin("2026-10-21T09:00:00.000000Z", ip="203.0.113.1", country="US", lat=32.8, lon=-96.8, session_id="S-x")
    b = signin("2026-10-21T09:20:00.000000Z", ip="203.0.113.2", country="NL", lat=52.4, lon=4.9, session_id="S-x")
    pos = run("TT-SIGNIN-002", h + [a, b])
    assert any(f.level == "confirmed" for f in pos)
    # a weekend trip is not impossible travel
    trip = [signin("2026-10-21T09:00:00.000000Z"),
            signin("2026-10-23T09:00:00.000000Z", ip="198.51.100.150", country="ES", lat=40.4, lon=-3.7)]
    assert run("TT-SIGNIN-002", h + trip) == []


def test_new_device():
    h = history()
    pos = run("TT-SIGNIN-003", h + [signin("2026-10-21T10:00:00.000000Z", ip="203.0.113.9", country="US",
                                           device_os="Linux", device_browser="Chrome 126.0.0",
                                           user_agent="python-requests/2.31.0")])
    assert pos and pos[0].level == "probable"
    assert run("TT-SIGNIN-003", h + [signin("2026-10-21T10:00:00.000000Z")]) == []


def test_legacy_protocol():
    h = history()
    pos = run("TT-SIGNIN-004", h + [signin("2026-10-21T02:00:00.000000Z", ip="203.0.113.20", client_app="IMAP4",
                                           interactive=0)])
    assert pos and pos[0].level == "probable"
    assert run("TT-SIGNIN-004", h + [signin("2026-10-21T02:00:00.000000Z", client_app="Browser")]) == []


def test_single_factor_from_new_ip():
    h = history()
    pos = run("TT-SIGNIN-005", h + [signin("2026-10-21T02:00:00.000000Z", ip="203.0.113.20", country="DE",
                                           auth_requirement="singleFactorAuthentication")])
    assert pos and pos[0].level == "probable"
    neg = run("TT-SIGNIN-005", h + [signin("2026-10-21T02:00:00.000000Z",
                                           auth_requirement="singleFactorAuthentication")])
    assert neg == []   # single factor from the account's usual address is out of scope


def test_failures_then_success():
    h = history()
    fails = [signin(f"2026-10-21T02:0{i}:00.000000Z", ip="203.0.113.30", outcome="failure", session_id="")
             for i in range(4)]
    ok = signin("2026-10-21T03:00:00.000000Z", ip="203.0.113.30", country="DE")
    pos = run("TT-SIGNIN-006", h + fails + [ok],
              failed_users={"203.0.113.30": {USER, "b@contoso.example", "c@contoso.example"}})
    assert pos and pos[0].level == "confirmed"
    assert run("TT-SIGNIN-006", h + fails[:2] + [ok]) == []   # two failures are not a pattern


def test_noninteractive_token_use():
    h = history()
    pos = run("TT-SIGNIN-007", h + [signin("2026-10-21T10:00:00.000000Z", ip="203.0.113.40", country="SG",
                                           source="entra_signin_noninteractive", interactive=0,
                                           device_os="Linux", device_browser="")])
    assert pos and pos[0].level == "probable"
    neg = run("TT-SIGNIN-007", h + [signin("2026-10-21T10:00:00.000000Z", source="entra_signin_noninteractive",
                                           interactive=0)])
    assert neg == []


# --- mailbox, auth, app and file rules ----------------------------------------------


def rule_event(**details):
    return ev("2026-10-21T10:14:00.000000Z", source="ual_exchange_admin", category="mail_rule",
              action="inbox_rule.create", operation="New-InboxRule", ip="203.0.113.77", details=details)


def test_hiding_inbox_rule():
    h = history()
    pos = run("TT-MAIL-001", h + [rule_event(rule_name="..", keywords=["invoice", "payment"],
                                             move_to_folder="RSS Subscriptions", mark_as_read=True)])
    assert pos and pos[0].level == "probable"
    conf = run("TT-MAIL-001", h + [rule_event(rule_name="..", move_to_folder="RSS Subscriptions")],
               flagged_ips={"203.0.113.77"}, flagged_sessions={"S-x"})
    assert conf and conf[0].level in ("probable", "confirmed")
    internal = rule_event(rule_name="Invoices to accounts", forward_to="accounts@contoso.example")
    assert run("TT-MAIL-001", h + [internal]) == []


def test_mailbox_forwarding():
    h = history()
    fwd = ev("2026-10-21T10:30:00.000000Z", source="ual_exchange_admin", category="mailbox_config",
             action="mailbox.forwarding_set", ip="203.0.113.77", details={"forward_to": "x@relay.example.net"})
    assert run("TT-MAIL-002", h + [fwd])[0].level == "probable"
    other = ev("2026-10-21T10:30:00.000000Z", source="ual_exchange_admin", category="mailbox_config",
               action="mailbox.update", ip="192.0.2.10", details={})
    assert run("TT-MAIL-002", h + [other]) == []


def test_delegate_permission():
    h = history()
    perm = ev("2026-10-21T10:30:00.000000Z", source="ual_exchange_admin", category="mailbox_config",
              action="mailbox.folder_permission_add", ip="203.0.113.77", details={"grantee": "Default"})
    assert run("TT-MAIL-003", h + [perm])[0].level == "probable"
    assert run("TT-MAIL-003", h + [rule_event()]) == []


def test_mail_access_from_flagged_session():
    h = history()
    acc = ev("2026-10-21T10:20:00.000000Z", source="ual_mailbox_items", category="mail_access",
             action="mail.items_accessed", ip="203.0.113.77", session_id="S-x", details={"item_count": 25})
    pos = run("TT-MAIL-004", h + [acc], flagged_ips={"203.0.113.77"}, flagged_sessions={"S-x"})
    assert pos and pos[0].level == "confirmed"
    assert run("TT-MAIL-004", h + [acc]) == []   # nothing flagged: no link to attacker access


def test_legacy_mail_access():
    h = history()
    imap = ev("2026-10-21T04:00:00.000000Z", source="ual_mailbox_items", category="mail_access",
              action="mail.items_accessed", ip="203.0.113.121", client_app="IMAP4", details={"item_count": 120})
    assert run("TT-MAIL-005", h + [imap])[0].level == "probable"
    owa = ev("2026-10-21T04:00:00.000000Z", source="ual_mailbox_items", category="mail_access",
             action="mail.items_accessed", ip="203.0.113.121", client_app="OWA")
    assert run("TT-MAIL-005", h + [owa]) == []


def test_mfa_change():
    h = history()
    reg = ev("2026-10-21T10:06:00.000000Z", source="ual_azuread", category="auth_method",
             action="auth.security_info_registered", ip="203.0.113.77", session_id="S-x")
    assert run("TT-AUTH-001", h + [reg], flagged_sessions={"S-x"})[0].level == "confirmed"
    own = ev("2026-10-21T10:06:00.000000Z", source="ual_azuread", category="auth_method",
             action="auth.security_info_registered", ip="192.0.2.10",
             user_agent=h[0].user_agent, device_os="Windows10", device_browser="Edge 128.0.0")
    assert run("TT-AUTH-001", h + [own])[0].level == "possible"
    assert run("TT-AUTH-001", h) == []


def test_device_registration():
    h = history()
    dev = ev("2026-10-21T10:06:00.000000Z", source="ual_azuread", category="device", action="device.register",
             ip="203.0.113.77")
    assert run("TT-AUTH-002", h + [dev])
    assert run("TT-AUTH-002", h) == []


def consent(scopes, ip="192.0.2.10", app="7d1c3a90-4b2e-4f6a-9c11-5e2a8b7f0d42"):
    return ev("2026-10-21T10:02:00.000000Z", source="ual_azuread", category="app_consent", action="app.consent",
              ip=ip, app_id=app, details={"scopes": scopes, "app_name": "Viewer"})


def test_oauth_consent():
    h = history()
    pos = run("TT-APP-001", h + [consent(["Mail.ReadWrite", "offline_access", "User.Read"])])
    assert pos and pos[0].level == "probable"
    assert run("TT-APP-001", h + [consent(["User.Read", "openid", "profile"])]) == []


def test_app_mail_access_after_consent():
    h = history()
    c = consent(["Mail.ReadWrite", "offline_access"])
    acc = ev("2026-10-21T10:40:00.000000Z", source="ual_mailbox_items", category="mail_access",
             action="mail.items_accessed", ip="203.0.113.150", app_id="7d1c3a90-4b2e-4f6a-9c11-5e2a8b7f0d42")
    pos = run("TT-APP-002", h + [c, acc])
    assert pos and pos[0].level == "confirmed"
    other = ev("2026-10-21T10:40:00.000000Z", source="ual_mailbox_items", category="mail_access",
               action="mail.items_accessed", ip="192.0.2.10", app_id="d3590ed6-52b3-4102-aeff-aad2292ab01c")
    assert run("TT-APP-002", h + [c, other]) == []


def test_bulk_download_against_own_history():
    h = history()
    burst = [ev(f"2026-10-21T10:{i:02d}:00.000000Z", source="ual_sharepoint", category="file_access",
                action="file.downloaded", ip="203.0.113.77") for i in range(30)]
    pos = run("TT-FILE-001", h + burst)
    assert pos and pos[0].level == "probable" and pos[0].extra["threshold"] == 15
    assert run("TT-FILE-001", h + burst[:10]) == []


def test_external_sharing():
    h = history()
    anon = ev("2026-10-21T11:00:00.000000Z", source="ual_sharepoint", category="sharing",
              action="sharing.anonymous_link", ip="203.0.113.77", details={"file_name": "a.xlsx"})
    assert run("TT-FILE-002", h + [anon])[0].level == "probable"
    internal = ev("2026-10-21T11:00:00.000000Z", source="ual_sharepoint", category="sharing",
                  action="sharing.invitation", ip="192.0.2.10", details={"share_target": "b@contoso.example"})
    assert run("TT-FILE-002", h + [internal]) == []


# --- capability -----------------------------------------------------------------------


def _coverage(statuses: dict[str, str]):
    return {"sources": [{"source": s, "status": st, "covers_first": "2026-10-01T00:00:00.000000Z",
                         "covers_last": "2026-10-30T00:00:00.000000Z"} for s, st in statuses.items()], "gaps": []}


def test_missing_source_reports_could_not_be_assessed():
    _, rules = load_rules()
    rule = next(r for r in rules if r.id == "TT-SIGNIN-007")
    b = build_baseline(history(), WINDOW)
    cap = rule_capability(rule, _coverage({"entra_signin_interactive": "present"}), b, {"start": WINDOW}, history())
    assert cap["status"] == "not_assessable"
    assert "entra_signin_noninteractive (not supplied)" in cap["reasons"][0]


def test_auditing_absent_source_is_not_usable():
    _, rules = load_rules()
    rule = next(r for r in rules if r.id == "TT-MAIL-004")
    b = build_baseline(history(), WINDOW)
    cap = rule_capability(rule, _coverage({"ual_mailbox_items": "auditing_absent"}), b, {"start": WINDOW}, [])
    assert cap["status"] == "not_assessable" and "auditing appears to be off" in cap["reasons"][0]


def test_short_history_means_unusual_cannot_be_judged():
    _, rules = load_rules()
    rule = next(r for r in rules if r.id == "TT-SIGNIN-001")
    short = [e for e in history() if e.ts_utc >= "2026-10-15"]
    b = build_baseline(short, WINDOW)
    cap = rule_capability(rule, _coverage({"entra_signin_interactive": "present"}), b, {"start": WINDOW}, short)
    assert cap["status"] == "not_assessable" and "needs at least 14 days" in cap["reasons"][0]


def test_csv_signins_without_coordinates_cannot_show_impossible_travel():
    _, rules = load_rules()
    rule = next(r for r in rules if r.id == "TT-SIGNIN-002")
    no_geo = [signin("2026-10-21T09:00:00.000000Z", lat=None, lon=None)]
    b = build_baseline(history(), WINDOW)
    cap = rule_capability(rule, _coverage({"entra_signin_interactive": "present"}), b, {"start": WINDOW}, no_geo)
    assert cap["status"] == "not_assessable" and "coordinates" in cap["reasons"][0]


@pytest.mark.parametrize("sid", ["degraded_no_signins", "degraded_retention_7d", "degraded_no_mailbox_audit", "demo_bec"])
def test_corpus_rules_that_cannot_run_say_so(corpus_dir, tmp_path, sid):
    import json

    from tenanttrace.case import Case
    from tenanttrace.pipeline import analyze, coverage, ingest

    gt = json.loads((corpus_dir / sid / "ground_truth.json").read_text(encoding="utf-8"))
    case = Case(tmp_path / sid)
    ingest(corpus_dir / sid / "exports", case, force=True)
    coverage(case, user=gt["primary_user"], collected_at=gt["collected_at"])
    res = analyze(case)
    cap = {c["rule_id"]: c for c in res["capability"]}
    for rid in gt["expected_not_assessable"]:
        assert cap[rid]["status"] == "not_assessable" and cap[rid]["findings"] == 0 and cap[rid]["reasons"], rid
    # a rule that could not run never appears as "assessed with no findings"
    for c in res["capability"]:
        if c["status"] == "not_assessable":
            assert c["reasons"]
