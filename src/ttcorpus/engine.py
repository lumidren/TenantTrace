"""Turn a scenario description into a list of activities.

A scenario YAML file describes the tenant (users, roles, home locations), the period, the
benign baseline behaviour, scripted attack and benign steps, the exports to write and any
degradation. The engine produces SignIn and AuditOp activities in time order plus a
ground-truth record of what happened.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from ttcorpus.model import (
    APPS,
    LOCATIONS,
    RESOURCES,
    App,
    AuditOp,
    Device,
    Ids,
    SignIn,
    User,
    uk_offset,
    utc,
)

# Record type integers from the Office 365 Management Activity API AuditLogRecordType enum
# (see docs/sources/microsoft-formats.md).
RT = {
    "ExchangeAdmin": 1,
    "ExchangeItem": 2,
    "ExchangeItemGroup": 3,
    "SharePoint": 4,
    "SharePointFileOperation": 6,
    "AzureActiveDirectory": 8,
    "AzureActiveDirectoryAccountLogon": 9,
    "SharePointSharingOperation": 14,
    "AzureActiveDirectoryStsLogon": 15,
    "ExchangeItemAggregated": 50,
}

UA_WIN_EDGE = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
               "Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0")
UA_MAC_SAFARI = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) "
                 "Version/17.5 Safari/605.1.15")
UA_IPHONE_OUTLOOK = "Outlook-iOS/2.0"
UA_ANDROID_OUTLOOK = "Outlook-Android/2.0"
UA_OUTLOOK_DESKTOP = "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.17928; Pro)"
UA_ATTACKER = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
               "Chrome/126.0.0.0 Safari/537.36")
UA_PYTHON = "python-requests/2.31.0"
UA_IMAP = "IMAP4 client"

USER_AGENTS = {
    "win_edge": UA_WIN_EDGE,
    "mac_safari": UA_MAC_SAFARI,
    "iphone_outlook": UA_IPHONE_OUTLOOK,
    "android_outlook": UA_ANDROID_OUTLOOK,
    "outlook_desktop": UA_OUTLOOK_DESKTOP,
    "attacker_linux": UA_ATTACKER,
    "python": UA_PYTHON,
    "imap": UA_IMAP,
}


@dataclass
class World:
    spec: dict[str, Any]
    ids: Ids
    tenant_id: str
    domain: str
    users: dict[str, User]
    period_start: datetime
    period_end: datetime
    signins: list[SignIn] = field(default_factory=list)
    ops: list[AuditOp] = field(default_factory=list)
    sessions: dict[str, dict[str, Any]] = field(default_factory=dict)  # named attacker/benign sessions
    truth_events: list[dict[str, Any]] = field(default_factory=list)
    infra: dict[str, dict[str, Any]] = field(default_factory=dict)      # named IP endpoints

    def user(self, key: str) -> User:
        if key in self.users:
            return self.users[key]
        for u in self.users.values():
            if u.upn == key:
                return u
        raise KeyError(f"unknown user {key!r}")


def build_world(spec: dict[str, Any]) -> World:
    ids = Ids(int(spec.get("seed", 1)))
    tenant = spec["tenant"]
    domain = tenant["domain"]
    users: dict[str, User] = {}
    for i, u in enumerate(spec["users"]):
        key = u["key"]
        upn = f"{u['alias']}@{domain}"
        user = User(
            upn=upn,
            display=u["display"],
            object_id=ids.uuid(),
            role=u.get("role", "staff"),
            home=u.get("home", "leeds"),
            office_ip=u.get("office_ip", "192.0.2.10"),
            home_ip=u.get("home_ip", f"198.51.100.{20 + i}"),
            mobile_ip=u.get("mobile_ip", f"2001:db8:100::{i + 1:x}"),
        )
        user.devices["laptop"] = Device(
            "laptop", ids.uuid(), f"HL-LT-{100 + i}", "Windows10", "Edge 128.0.0", UA_WIN_EDGE, True, True,
            "Azure AD joined")
        phone_ua = UA_IPHONE_OUTLOOK if i % 2 == 0 else UA_ANDROID_OUTLOOK
        user.devices["phone"] = Device(
            "phone", ids.uuid(), f"{u['alias']}-phone", "Ios" if i % 2 == 0 else "Android", "", phone_ua,
            False, False, "Azure AD registered")
        users[key] = user
    w = World(
        spec=spec,
        ids=ids,
        tenant_id=tenant.get("id") or ids.uuid(),
        domain=domain,
        users=users,
        period_start=utc(spec["period"]["start"]),
        period_end=utc(spec["period"]["end"]),
    )
    for key, ep in (spec.get("infra") or {}).items():
        w.infra[key] = dict(ep)
    return w


# ----------------------------------------------------------------------------- helpers

def _session(w: World, user: User, kind: str, t: datetime) -> str:
    """Stable baseline session id per user, device kind and ISO week."""
    year, week, _ = t.isocalendar()
    name = f"base:{user.upn}:{kind}:{year}-{week}"
    if name not in w.sessions:
        w.sessions[name] = {"id": w.ids.uuid()}
    return w.sessions[name]["id"]


def add_signin(w: World, **kw: Any) -> SignIn:
    s = SignIn(**kw)
    s.token_id = s.token_id or w.ids.token()
    s.correlation_id = s.correlation_id or w.ids.uuid()
    s.request_id = s.request_id or w.ids.uuid()
    w.signins.append(s)
    return s


def add_op(w: World, **kw: Any) -> AuditOp:
    op = AuditOp(**kw)
    op.record_id = op.record_id or w.ids.uuid()
    w.ops.append(op)
    return op


def _jitter(w: World, base: datetime, minutes: float) -> datetime:
    return base + timedelta(seconds=w.ids.rng.uniform(-minutes * 60, minutes * 60))


def _site(w: World, user: User) -> str:
    alias = user.upn.split("@")[0].replace(".", "_")
    tenant_short = w.domain.split(".")[0]
    return f"https://{tenant_short}-my.sharepoint.example/personal/{alias}_{tenant_short}_example"


TEAM_SITE = "https://{t}.sharepoint.example/sites/Finance"

FILE_NAMES = [
    "Q3 supplier payments.xlsx", "Invoice register 2026.xlsx", "Board pack October.pptx",
    "Remittance advice template.docx", "Bank details change form.pdf", "Payroll summary.xlsx",
    "Vendor master list.xlsx", "Contract - freight services.docx", "Budget forecast FY27.xlsx",
    "Customer pricing 2026.xlsx", "Travel policy.pdf", "Team rota.xlsx", "Meeting notes.docx",
    "Credit control actions.xlsx", "Aged debtors report.xlsx", "Purchase order log.xlsx",
]


def file_payload(w: World, user: User, name: str | None = None, team: bool = False,
                 event_source: str = "SharePoint") -> dict[str, Any]:
    name = name or w.ids.rng.choice(FILE_NAMES)
    ext = name.rsplit(".", 1)[-1]
    site = TEAM_SITE.format(t=w.domain.split(".")[0]) if team else _site(w, user)
    folder = "Shared Documents" if team else "Documents"
    return {
        "SiteUrl": site + "/",
        "SourceFileName": name,
        "SourceFileExtension": ext,
        "SourceRelativeUrl": folder,
        "ObjectId": f"{site}/{folder}/{name}",
        "ItemType": "File",
        "EventSource": event_source,
        "ListItemUniqueId": w.ids.uuid(),
    }


# ----------------------------------------------------------------------------- baseline

def generate_baseline(w: World) -> None:
    prof = w.spec.get("baseline", {})
    activity = float(prof.get("activity", 1.0))
    rng = w.ids.rng
    day = w.period_start.replace(hour=0, minute=0, second=0, microsecond=0)
    while day < w.period_end:
        for key, user in w.users.items():
            ucfg = next(u for u in w.spec["users"] if u["key"] == key)
            if ucfg.get("baseline") is False:
                continue
            start_after = ucfg.get("joined")
            if start_after and day < utc(start_after):
                continue
            _baseline_day(w, user, ucfg, day, activity * float(ucfg.get("activity", 1.0)))
        day += timedelta(days=1)
    _ = rng


def _baseline_day(w: World, user: User, ucfg: dict[str, Any], day: datetime, activity: float) -> None:
    rng = w.ids.rng
    off = uk_offset(day + timedelta(hours=12))
    weekday = day.weekday() < 5
    loc = LOCATIONS[user.home]
    travel = _travel_for(ucfg, day)
    if travel is not None:
        loc = LOCATIONS[travel["location"]]
    laptop = user.devices["laptop"]
    phone = user.devices["phone"]

    if weekday and rng.random() < 0.95:
        if travel is not None:
            ip = travel["ip"]
        elif day.weekday() == 4 or ucfg.get("remote"):
            ip = user.home_ip
        else:
            ip = user.office_ip
        if ucfg.get("vpn"):
            ip = w.infra[ucfg["vpn"]]["ip"]
            loc = LOCATIONS[w.infra[ucfg["vpn"]]["location"]]
        local_start = day + timedelta(hours=8, minutes=30) - off
        t = _jitter(w, local_start, 35)
        sess = _session(w, user, "laptop", t)
        full_mfa = day.weekday() == 0 or rng.random() < 0.15
        add_signin(
            w, t=t, user=user, ip=ip, loc=loc, device=laptop, app=APPS["office"], resource=RESOURCES["office"],
            client_app="Browser", interactive=True, success=True,
            auth_requirement="multiFactorAuthentication",
            mfa_detail="MFA completed in Azure AD" if full_mfa else "MFA requirement satisfied by claim in the token",
            session_id=sess,
        )
        _mirror_logon(w, w.signins[-1])
        # Outlook desktop and Teams refresh tokens through the working day (non-interactive)
        end = day + timedelta(hours=17, minutes=30) - off
        t2 = t + timedelta(minutes=rng.randint(5, 20))
        while t2 < end:
            app = APPS["outlook"] if rng.random() < 0.7 else APPS["teams"]
            res = RESOURCES["exchange"] if app is APPS["outlook"] else RESOURCES["graph"]
            add_signin(
                w, t=t2, user=user, ip=ip, loc=loc, device=laptop, app=app, resource=res,
                client_app="Mobile Apps and Desktop clients", interactive=False, success=True,
                auth_requirement="multiFactorAuthentication",
                mfa_detail="MFA requirement satisfied by claim in the token", session_id=sess,
            )
            t2 += timedelta(minutes=rng.randint(55, 95))
        # mailbox and file activity during the day
        n_sync = max(1, int(rng.randint(2, 4) * activity))
        for _ in range(n_sync):
            ts = t + timedelta(minutes=rng.randint(10, 520))
            if ts >= end:
                continue
            mail_access(w, user, ts, ip, sess, APPS["outlook"].app_id, "Sync",
                        client_info="Client=MSExchangeRPC", count=1, ua=UA_OUTLOOK_DESKTOP)
        if rng.random() < 0.5:
            ts = t + timedelta(minutes=rng.randint(10, 400))
            mail_access(w, user, ts, ip, sess, APPS["owa"].app_id, "Bind",
                        client_info="Client=OWA;Action=ViaProxy", count=rng.randint(1, 4), ua=laptop.user_agent)
        for _ in range(int(rng.randint(2, 6) * activity)):
            ts = t + timedelta(minutes=rng.randint(10, 520))
            if ts < end:
                add_op(w, t=ts, user=user, workload="Exchange", record_type=RT["ExchangeItem"], operation="Send",
                       ip=ip, session_id=sess, app_id=APPS["outlook"].app_id, user_agent=UA_OUTLOOK_DESKTOP,
                       payload={"ClientInfoString": "Client=MSExchangeRPC", "Subject": "Re: weekly figures",
                                "folder": "Sent Items"})
        n_files = int(rng.randint(3, 10) * activity * float(ucfg.get("file_activity", 1.0)))
        for _ in range(n_files):
            ts = t + timedelta(minutes=rng.randint(10, 520))
            if ts >= end:
                continue
            op = rng.choices(["FileAccessed", "FileModified", "FileDownloaded", "FileUploaded"], [6, 3, 2, 1])[0]
            team = rng.random() < 0.5
            ws = "SharePoint" if team else "OneDrive"
            add_op(w, t=ts, user=user, workload=ws, record_type=RT["SharePointFileOperation"], operation=op,
                   ip=ip, session_id=sess, app_id=APPS["sharepoint"].app_id, user_agent=laptop.user_agent,
                   payload=file_payload(w, user, team=team))
        if rng.random() < 0.12 * activity:
            ts = t + timedelta(minutes=rng.randint(30, 480))
            colleague = rng.choice([u for u in w.users.values() if u is not user])
            pl = file_payload(w, user)
            pl.update({"TargetUserOrGroupName": colleague.upn, "TargetUserOrGroupType": "Member"})
            add_op(w, t=ts, user=user, workload="OneDrive", record_type=RT["SharePointSharingOperation"],
                   operation="SharingInvitationCreated", ip=ip, session_id=sess,
                   app_id=APPS["sharepoint"].app_id, user_agent=laptop.user_agent, payload=pl)
        if user.role == "admin":
            _admin_noise(w, user, t, ip, sess)

    # evening phone use
    if rng.random() < (0.55 if weekday else 0.3):
        ip = user.mobile_ip if travel is None else travel["ip"]
        t = _jitter(w, day + timedelta(hours=19, minutes=30) - off, 60)
        sess = _session(w, user, "phone", t)
        add_signin(
            w, t=t, user=user, ip=ip, loc=loc, device=phone, app=APPS["outlook_mobile"],
            resource=RESOURCES["exchange"], client_app="Mobile Apps and Desktop clients", interactive=False,
            success=True, auth_requirement="multiFactorAuthentication",
            mfa_detail="MFA requirement satisfied by claim in the token", session_id=sess,
        )
        mail_access(w, user, t + timedelta(minutes=1), ip, sess, APPS["outlook_mobile"].app_id, "Sync",
                    client_info="Client=REST;Client=RESTSystem;", count=1, ua=phone.user_agent)


def _travel_for(ucfg: dict[str, Any], day: datetime) -> dict[str, Any] | None:
    for tr in ucfg.get("travel", []) or []:
        if utc(tr["from"]) <= day < utc(tr["to"]):
            return tr
    return None


def _admin_noise(w: World, admin: User, t: datetime, ip: str, sess: str) -> None:
    rng = w.ids.rng
    if rng.random() < 0.25:
        target = rng.choice([u for u in w.users.values() if u is not admin])
        add_op(w, t=t + timedelta(minutes=rng.randint(20, 300)), user=admin, workload="Exchange",
               record_type=RT["ExchangeAdmin"], operation="Set-Mailbox", ip=ip, session_id=sess,
               app_id=APPS["exo_powershell"].app_id,
               payload={"ObjectId": target.display, "Parameters": [
                   {"Name": "Identity", "Value": target.upn},
                   {"Name": "RetainDeletedItemsFor", "Value": "30.00:00:00"}]})


def _mirror_logon(w: World, s: SignIn) -> None:
    """Interactive sign-ins also appear in the UAL as AzureActiveDirectoryStsLogon records."""
    add_op(w, t=s.t, user=s.user, workload="AzureActiveDirectory", record_type=RT["AzureActiveDirectoryStsLogon"],
           operation="UserLoggedIn" if s.success else "UserLoginFailed", ip=s.ip, session_id=s.session_id,
           app_id=s.app.app_id, user_agent=s.device.user_agent,
           result_status="Success" if s.success else "Failed",
           payload={"mirror_of": s.request_id, "error_code": s.error_code, "application_id": s.app.app_id,
                    "object_id": s.resource.app_id, "correlation_id": s.correlation_id},
           tags=dict(s.tags))


def mail_access(w: World, user: User, t: datetime, ip: str, sess: str, app_id: str, access: str,
                client_info: str, count: int, ua: str, folders: list[str] | None = None,
                tags: dict[str, Any] | None = None, actor: User | None = None) -> AuditOp:
    folders = folders or ["\\Inbox"]
    items = []
    for f in folders:
        items.append({"FolderPath": f, "Items": [
            {"InternetMessageId": f"<{w.ids.token(16)}@{w.domain}>", "SizeInBytes": w.ids.rng.randint(4000, 90000)}
            for _ in range(count)]})
    return add_op(w, t=t, user=actor or user, workload="Exchange", record_type=RT["ExchangeItemAggregated"],
                  operation="MailItemsAccessed", ip=ip, session_id=sess, app_id=app_id, user_agent=ua,
                  payload={"MailAccessType": access, "ClientInfoString": client_info, "Folders": items,
                           "OperationCount": count * len(folders), "MailboxOwnerUPN": user.upn},
                  tags=tags or {})


# ----------------------------------------------------------------------------- scripted steps

def _at(w: World, base: datetime, spec: Any) -> datetime:
    if isinstance(spec, str) and spec.startswith("+"):
        return base + _dur(spec[1:])
    return utc(str(spec))


def _dur(s: str) -> timedelta:
    s = s.strip()
    total = timedelta()
    num = ""
    for ch in s:
        if ch.isdigit() or ch == ".":
            num += ch
            continue
        v = float(num or 0)
        num = ""
        total += {"d": timedelta(days=v), "h": timedelta(hours=v), "m": timedelta(minutes=v),
                  "s": timedelta(seconds=v)}[ch]
    if num:
        total += timedelta(minutes=float(num))
    return total


def run_steps(w: World) -> None:
    for block in w.spec.get("scripts", []) or []:
        base = utc(block["start"])
        for step in block["steps"]:
            t = _at(w, base, step.get("at", "+0m"))
            fn = STEPS[step["do"]]
            fn(w, t, step, block)


def _endpoint(w: World, name: str) -> dict[str, Any]:
    ep = w.infra[name]
    return {"ip": ep["ip"], "loc": LOCATIONS[ep["location"]]}


def _device_for(w: World, user: User, step: dict[str, Any]) -> Device:
    dev = step.get("device")
    if dev in user.devices:
        return user.devices[dev]
    ua = USER_AGENTS.get(step.get("ua", "attacker_linux"), step.get("ua", UA_ATTACKER))
    key = f"unreg:{ua}"
    if key not in user.devices:
        browser = "Chrome 126.0.0" if "Chrome" in ua else ""
        os_ = "Linux" if "Linux" in ua else ("Windows10" if "Windows" in ua else "")
        user.devices[key] = Device(key, "", "", os_, browser, ua, False, False, "")
    return user.devices[key]


def _tags(step: dict[str, Any], block: dict[str, Any]) -> dict[str, Any]:
    tags = {"actor_kind": block.get("actor", "attacker"), "truth_id": step.get("id", "")}
    if step.get("expect"):
        tags["expect"] = step["expect"]
    return tags


def _ctx(w: World, step: dict[str, Any], user: User) -> tuple[str, str, str, str]:
    """(ip, session id, token id, user agent) for an action, from a named session or endpoint."""
    if step.get("session"):
        s = w.sessions[step["session"]]
        return s["ip"], s["id"], s["token"], s["ua"]
    if step.get("from") == "baseline":
        return user.office_ip, _session(w, user, "laptop", w.period_start), "", user.devices["laptop"].user_agent
    ep = _endpoint(w, step["from"])
    return ep["ip"], "", "", USER_AGENTS.get(step.get("ua", "attacker_linux"), UA_ATTACKER)


def step_signin(w: World, t: datetime, step: dict[str, Any], block: dict[str, Any]) -> None:
    user = w.user(step["user"])
    if step.get("from") == "baseline":
        ep = {"ip": user.office_ip, "loc": LOCATIONS[user.home]}
    else:
        ep = _endpoint(w, step["from"])
    dev = _device_for(w, user, step)
    app = APPS[step.get("app", "office")]
    res = RESOURCES[step.get("resource", "office")]
    sess_name = step.get("session")
    if sess_name and sess_name in w.sessions:
        sid = w.sessions[sess_name]["id"]
    else:
        sid = w.ids.uuid()
    count = int(step.get("count", 1))
    every = _dur(step.get("every", "40m"))
    success = step.get("success", True)
    for i in range(count):
        s = add_signin(
            w, t=t + every * i, user=user, ip=ep["ip"], loc=ep["loc"], device=dev, app=app, resource=res,
            client_app=step.get("client_app", "Browser"), interactive=step.get("interactive", True),
            success=success, error_code=int(step.get("error_code", 0 if success else 50126)),
            failure_reason=step.get("failure_reason", "" if success else
                                    "Error validating credentials due to invalid username or password."),
            auth_requirement=step.get("auth_requirement", "multiFactorAuthentication"),
            mfa_detail=step.get("mfa_detail", "MFA requirement satisfied by claim in the token"),
            session_id=sid if success else "", tags=_tags(step, block),
            auth_protocol=step.get("auth_protocol", "none"),
        )
        if s.interactive:
            _mirror_logon(w, s)
    if sess_name and success:
        w.sessions[sess_name] = {"id": sid, "ip": ep["ip"], "token": w.signins[-1].token_id,
                                 "ua": dev.user_agent, "user": user.upn, "app_id": app.app_id}


def step_spray(w: World, t: datetime, step: dict[str, Any], block: dict[str, Any]) -> None:
    ep = _endpoint(w, step["from"])
    users = [w.user(u) for u in step["users"]]
    rounds = int(step.get("rounds", 3))
    for r in range(rounds):
        for j, user in enumerate(users):
            dev = _device_for(w, user, {"ua": step.get("ua", "python")})
            s = add_signin(w, t=t + timedelta(minutes=30 * r, seconds=7 * j), user=user, ip=ep["ip"],
                           loc=ep["loc"], device=dev, app=APPS["office"], resource=RESOURCES["office"],
                           client_app=step.get("client_app", "Other clients"), interactive=True, success=False,
                           error_code=50126,
                           failure_reason="Error validating credentials due to invalid username or password.",
                           auth_requirement="singleFactorAuthentication", mfa_detail="",
                           tags=_tags(step, block))
            _mirror_logon(w, s)


def step_mfa_register(w: World, t: datetime, step: dict[str, Any], block: dict[str, Any]) -> None:
    user = w.user(step["user"])
    ip, sid, tok, ua = _ctx(w, step, user)
    op = step.get("operation", "User registered security info.")
    add_op(w, t=t, user=user, workload="AzureActiveDirectory", record_type=RT["AzureActiveDirectory"],
           operation=op, ip=ip, session_id=sid, token_id=tok, user_agent=ua, result_status="Success",
           payload={"method": step.get("method", "Microsoft Authenticator app"),
                    "detail": step.get("detail", "User registered Authenticator App with Notification and Code")},
           tags=_tags(step, block))


def step_inbox_rule(w: World, t: datetime, step: dict[str, Any], block: dict[str, Any]) -> None:
    user = w.user(step["user"])
    ip, sid, tok, ua = _ctx(w, step, user)
    params = [{"Name": "Name", "Value": step.get("name", ".")}]
    for k, v in (step.get("params") or {}).items():
        params.append({"Name": k, "Value": str(v)})
    params.append({"Name": "AlwaysDeleteOutlookRulesBlob", "Value": "False"})
    params.append({"Name": "Force", "Value": "False"})
    add_op(w, t=t, user=user, workload="Exchange", record_type=RT["ExchangeAdmin"],
           operation=step.get("operation", "New-InboxRule"), ip=ip + ":" + str(w.ids.rng.randint(1025, 65000))
           if ":" not in ip else ip, session_id=sid, token_id=tok, user_agent=ua,
           app_id=w.sessions.get(step.get("session", ""), {}).get("app_id", ""),
           payload={"ObjectId": f"{user.display}\\{step.get('name', '.')}", "Parameters": params,
                    "ClientInfoString": "Client=OWA;Action=ViaProxy"},
           tags=_tags(step, block))


def step_exchange_cmdlet(w: World, t: datetime, step: dict[str, Any], block: dict[str, Any]) -> None:
    actor = w.user(step["user"])
    target = w.user(step.get("target", step["user"]))
    ip, sid, tok, ua = _ctx(w, step, actor)
    params = [{"Name": "Identity", "Value": target.upn}]
    for k, v in (step.get("params") or {}).items():
        params.append({"Name": k, "Value": str(v)})
    add_op(w, t=t, user=actor, workload="Exchange", record_type=RT["ExchangeAdmin"], operation=step["cmdlet"],
           ip=ip, session_id=sid, token_id=tok, user_agent=ua,
           payload={"ObjectId": target.display, "Parameters": params,
                    "ClientInfoString": step.get("client_info", "Client=OWA;Action=ViaProxy")},
           tags=_tags(step, block))


def step_mail_access(w: World, t: datetime, step: dict[str, Any], block: dict[str, Any]) -> None:
    user = w.user(step["user"])
    ip, sid, tok, ua = _ctx(w, step, user)
    app_id = step.get("app_id") or w.sessions.get(step.get("session", ""), {}).get("app_id", APPS["owa"].app_id)
    n = int(step.get("events", 1))
    for i in range(n):
        op = mail_access(w, user, t + timedelta(minutes=2 * i), ip, sid, app_id, step.get("access", "Bind"),
                         client_info=step.get("client_info", "Client=OWA;Action=ViaProxy"),
                         count=int(step.get("items", 10)), ua=ua,
                         folders=step.get("folders"), tags=_tags(step, block))
        op.token_id = tok


def step_send(w: World, t: datetime, step: dict[str, Any], block: dict[str, Any]) -> None:
    user = w.user(step["user"])
    ip, sid, tok, ua = _ctx(w, step, user)
    for i, rcpt in enumerate(step.get("to", [])):
        add_op(w, t=t + timedelta(seconds=40 * i), user=user, workload="Exchange", record_type=RT["ExchangeItem"],
               operation="Send", ip=ip, session_id=sid, token_id=tok, user_agent=ua,
               payload={"ClientInfoString": "Client=OWA;Action=ViaProxy", "Subject": step.get("subject", ""),
                        "folder": "Sent Items", "recipient": w.user(rcpt).upn if rcpt in w.users else rcpt},
               tags=_tags(step, block))


def step_files(w: World, t: datetime, step: dict[str, Any], block: dict[str, Any]) -> None:
    user = w.user(step["user"])
    ip, sid, tok, ua = _ctx(w, step, user)
    n = int(step.get("count", 20))
    span = _dur(step.get("over", "15m"))
    op_name = step.get("operation", "FileDownloaded")
    team = step.get("team", True)
    names = list(FILE_NAMES)
    for i in range(n):
        name = names[i % len(names)] if i < len(names) else f"Archive {i:03d}.xlsx"
        ts = t + span * (i / max(1, n))
        add_op(w, t=ts, user=user, workload="SharePoint" if team else "OneDrive",
               record_type=RT["SharePointFileOperation"], operation=op_name, ip=ip, session_id=sid, token_id=tok,
               user_agent=ua, app_id=APPS["sharepoint"].app_id,
               payload=file_payload(w, user, name=name, team=team), tags=_tags(step, block))


def step_share(w: World, t: datetime, step: dict[str, Any], block: dict[str, Any]) -> None:
    user = w.user(step["user"])
    ip, sid, tok, ua = _ctx(w, step, user)
    n = int(step.get("count", 1))
    for i in range(n):
        pl = file_payload(w, user, name=FILE_NAMES[i % len(FILE_NAMES)], team=step.get("team", True))
        op = step.get("operation", "AnonymousLinkCreated")
        if step.get("target"):
            pl.update({"TargetUserOrGroupName": step["target"], "TargetUserOrGroupType": step.get("target_type", "Guest")})
        add_op(w, t=t + timedelta(seconds=30 * i), user=user, workload="SharePoint",
               record_type=RT["SharePointSharingOperation"], operation=op, ip=ip, session_id=sid, token_id=tok,
               user_agent=ua, app_id=APPS["sharepoint"].app_id, payload=pl, tags=_tags(step, block))


def step_consent(w: World, t: datetime, step: dict[str, Any], block: dict[str, Any]) -> None:
    user = w.user(step["user"])
    ip, sid, tok, ua = _ctx(w, step, user)
    app = step["app"]
    add_op(w, t=t, user=user, workload="AzureActiveDirectory", record_type=RT["AzureActiveDirectory"],
           operation="Consent to application.", ip=ip, session_id=sid, token_id=tok, user_agent=ua,
           result_status="Success",
           payload={"app_id": app["id"], "app_name": app["name"], "scopes": app.get("scopes", []),
                    "is_admin_consent": bool(step.get("admin_consent", False)), "on_behalf_of_all": False},
           tags=_tags(step, block))
    w.infra.setdefault("apps", {})[app["name"]] = app


def step_app_mail_access(w: World, t: datetime, step: dict[str, Any], block: dict[str, Any]) -> None:
    user = w.user(step["user"])
    ep = _endpoint(w, step["from"])
    app = step["app"]
    n = int(step.get("events", 3))
    for i in range(n):
        mail_access(w, user, t + timedelta(minutes=17 * i), ep["ip"], "", app["id"], "Bind",
                    client_info="Client=REST;Client=RESTSystem;", count=int(step.get("items", 25)),
                    ua=USER_AGENTS.get(step.get("ua", "python"), UA_PYTHON), tags=_tags(step, block))


def step_device_register(w: World, t: datetime, step: dict[str, Any], block: dict[str, Any]) -> None:
    user = w.user(step["user"])
    ip, sid, tok, ua = _ctx(w, step, user)
    add_op(w, t=t, user=user, workload="AzureActiveDirectory", record_type=RT["AzureActiveDirectory"],
           operation="Register device.", ip=ip, session_id=sid, token_id=tok, user_agent=ua, result_status="Success",
           payload={"device_name": step.get("device_name", "DESKTOP-7Q2K9ZX"), "os": step.get("os", "Windows")},
           tags=_tags(step, block))


def step_delete_mail(w: World, t: datetime, step: dict[str, Any], block: dict[str, Any]) -> None:
    user = w.user(step["user"])
    ip, sid, tok, ua = _ctx(w, step, user)
    add_op(w, t=t, user=user, workload="Exchange", record_type=RT["ExchangeItemGroup"],
           operation=step.get("operation", "SoftDelete"), ip=ip, session_id=sid, token_id=tok, user_agent=ua,
           payload={"ClientInfoString": "Client=OWA;Action=ViaProxy", "count": int(step.get("count", 5)),
                    "folder": step.get("folder", "\\Sent Items")},
           tags=_tags(step, block))


STEPS = {
    "signin": step_signin,
    "spray": step_spray,
    "mfa_register": step_mfa_register,
    "inbox_rule": step_inbox_rule,
    "exchange_cmdlet": step_exchange_cmdlet,
    "mail_access": step_mail_access,
    "send": step_send,
    "files": step_files,
    "share": step_share,
    "consent": step_consent,
    "app_mail_access": step_app_mail_access,
    "device_register": step_device_register,
    "delete_mail": step_delete_mail,
}


def simulate(spec: dict[str, Any]) -> World:
    w = build_world(spec)
    generate_baseline(w)
    run_steps(w)
    # keep only activity inside the scenario period (the first baseline day may start before it)
    w.signins = [s for s in w.signins if w.period_start <= s.t <= w.period_end]
    w.ops = [o for o in w.ops if w.period_start <= o.t <= w.period_end]
    w.signins.sort(key=lambda s: (s.t, s.request_id))
    w.ops.sort(key=lambda o: (o.t, o.record_id))
    return w


def ts(dt: datetime) -> datetime:
    return dt.astimezone(timezone.utc)
