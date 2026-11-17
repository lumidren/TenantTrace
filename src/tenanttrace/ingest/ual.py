"""Normalize unified audit log records (the AuditData JSON) into events.

Field names follow docs/sources/microsoft-formats.md section 1 and were written from that
document, not from the test-data generator. Where Microsoft's documentation disagrees with
itself or is silent, both spellings are accepted (see docs/VERIFY.md).
"""

from __future__ import annotations

import re
from typing import Any

from tenanttrace.ingest.timeparse import TimeParseError, parse_ts
from tenanttrace.schema import Event

# 1c-3 AuditLogRecordType (confirmed values used here)
RECORD_TYPES = {
    1: "ExchangeAdmin", 2: "ExchangeItem", 3: "ExchangeItemGroup", 4: "SharePoint",
    6: "SharePointFileOperation", 7: "OneDrive", 8: "AzureActiveDirectory",
    9: "AzureActiveDirectoryAccountLogon", 14: "SharePointSharingOperation",
    15: "AzureActiveDirectoryStsLogon", 19: "ExchangeAggregatedOperation", 36: "SharePointListOperation",
    50: "ExchangeItemAggregated",
}
RECORD_TYPE_BY_NAME = {v.lower(): k for k, v in RECORD_TYPES.items()}

SOURCE_BY_RECORD_TYPE = {
    1: "ual_exchange_admin",
    2: "ual_mailbox_items", 3: "ual_mailbox_items", 19: "ual_mailbox_items", 50: "ual_mailbox_items",
    4: "ual_sharepoint", 6: "ual_sharepoint", 7: "ual_sharepoint", 14: "ual_sharepoint", 36: "ual_sharepoint",
    8: "ual_azuread",
    9: "ual_azuread_logon", 15: "ual_azuread_logon",
}

# Operation (lower case, trailing period removed) -> (category, normalized action)
OPERATIONS: dict[str, tuple[str, str]] = {
    # inbox rules (1d-2, 1d-4)
    "new-inboxrule": ("mail_rule", "inbox_rule.create"),
    "set-inboxrule": ("mail_rule", "inbox_rule.update"),
    "enable-inboxrule": ("mail_rule", "inbox_rule.update"),
    "updateinboxrules": ("mail_rule", "inbox_rule.update"),
    "remove-inboxrule": ("mail_rule", "inbox_rule.delete"),
    "disable-inboxrule": ("mail_rule", "inbox_rule.disable"),
    # mailbox configuration and delegation (1d-5, 1d-6)
    "set-mailbox": ("mailbox_config", "mailbox.update"),
    "add-mailboxpermission": ("mailbox_config", "mailbox.permission_add"),
    "remove-mailboxpermission": ("mailbox_config", "mailbox.permission_remove"),
    "add-recipientpermission": ("mailbox_config", "mailbox.recipient_permission_add"),
    "add-mailboxfolderpermission": ("mailbox_config", "mailbox.folder_permission_add"),
    "set-mailboxfolderpermission": ("mailbox_config", "mailbox.folder_permission_add"),
    "addfolderpermissions": ("mailbox_config", "mailbox.folder_permission_add"),
    "modifyfolderpermissions": ("mailbox_config", "mailbox.folder_permission_add"),
    "removefolderpermissions": ("mailbox_config", "mailbox.folder_permission_remove"),
    "updatecalendardelegation": ("mailbox_config", "mailbox.calendar_delegation"),
    # mailbox items (1e-3)
    "mailitemsaccessed": ("mail_access", "mail.items_accessed"),
    "messagebind": ("mail_access", "mail.message_bind"),
    "folderbind": ("mail_access", "mail.folder_bind"),
    "searchqueryinitiated": ("mail_access", "mail.search"),
    "attachmentaccess": ("mail_access", "mail.attachment_access"),
    "send": ("mail_send", "mail.send"),
    "sendas": ("mail_send", "mail.send_as"),
    "sendonbehalf": ("mail_send", "mail.send_on_behalf"),
    "softdelete": ("mail_delete", "mail.soft_delete"),
    "harddelete": ("mail_delete", "mail.hard_delete"),
    "movetodeleteditems": ("mail_delete", "mail.move_to_deleted"),
    "move": ("mail_access", "mail.move"),
    "create": ("mail_access", "mail.create"),
    "update": ("mail_access", "mail.update"),
    "mailboxlogin": ("signin", "mail.mailbox_login"),
    # SharePoint / OneDrive (1f-4)
    "fileaccessed": ("file_access", "file.accessed"),
    "filepreviewed": ("file_access", "file.previewed"),
    "filedownloaded": ("file_access", "file.downloaded"),
    "filesyncdownloadedfull": ("file_access", "file.sync_downloaded"),
    "fileuploaded": ("file_access", "file.uploaded"),
    "filesyncuploadedfull": ("file_access", "file.uploaded"),
    "filemodified": ("file_access", "file.modified"),
    "filedeleted": ("file_access", "file.deleted"),
    "anonymouslinkcreated": ("sharing", "sharing.anonymous_link"),
    "anonymouslinkupdated": ("sharing", "sharing.anonymous_link"),
    "anonymouslinkused": ("sharing", "sharing.anonymous_link_used"),
    "anonymouslinkremoved": ("sharing", "sharing.link_removed"),
    "companylinkcreated": ("sharing", "sharing.company_link"),
    "companylinkused": ("sharing", "sharing.company_link_used"),
    "sharinginvitationcreated": ("sharing", "sharing.invitation"),
    "sharinginvitationaccepted": ("sharing", "sharing.invitation_accepted"),
    "sharingset": ("sharing", "sharing.set"),
    "sharingrevoked": ("sharing", "sharing.revoked"),
    "securelinkcreated": ("sharing", "sharing.secure_link"),
    "addedtosecurelink": ("sharing", "sharing.secure_link"),
    "securelinkused": ("sharing", "sharing.secure_link_used"),
    # Entra in the UAL (1g-2, 1g-3)
    "userloggedin": ("signin", "signin"),
    "userloginfailed": ("signin", "signin"),
    "consent to application": ("app_consent", "app.consent"),
    "add delegated permission grant": ("app_consent", "app.permission_grant"),
    "add app role assignment to service principal": ("app_consent", "app.role_grant"),
    "add app role assignment grant to user": ("app_consent", "app.role_grant"),
    "add service principal": ("app_consent", "app.service_principal_add"),
    "add service principal credentials": ("app_consent", "app.credentials_add"),
    "user registered security info": ("auth_method", "auth.security_info_registered"),
    "user changed default security info": ("auth_method", "auth.security_info_changed"),
    "user deleted security info": ("auth_method", "auth.security_info_deleted"),
    "admin registered security info": ("auth_method", "auth.security_info_registered"),
    "admin deleted security info": ("auth_method", "auth.security_info_deleted"),
    "register device": ("device", "device.register"),
    "add registered owner to device": ("device", "device.owner_add"),
    "add registered users to device": ("device", "device.owner_add"),
    "add device": ("device", "device.register"),
    "update user": ("directory", "directory.user_update"),
    "reset user password": ("directory", "directory.password_reset"),
    "change user password": ("directory", "directory.password_change"),
    "add member to role": ("directory", "directory.role_add"),
}

_GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_SCOPE = re.compile(r"Scope:\s*([^,\]\[]*)")
_SPLIT = re.compile(r"[;,]")


def op_key(operation: str) -> str:
    return operation.strip().rstrip(".").strip().lower()


def record_type_int(v: Any) -> int | None:
    if isinstance(v, int):
        return v
    if v is None:
        return None
    s = str(v).strip()
    if s.isdigit():
        return int(s)
    return RECORD_TYPE_BY_NAME.get(s.lower())


def split_ip(raw: str | None) -> str:
    """Strip a port from ClientIP values such as 203.0.113.5:51234 or [2001:db8::1]:443."""
    if not raw:
        return ""
    s = str(raw).strip()
    if s.startswith("["):
        return s[1:s.index("]")] if "]" in s else s.strip("[]")
    if s.count(":") == 1:
        return s.split(":", 1)[0]
    return s


def _nv(items: Any, name_key: str = "Name", value_key: str = "Value") -> dict[str, Any]:
    out: dict[str, Any] = {}
    if isinstance(items, list):
        for it in items:
            if isinstance(it, dict) and name_key in it:
                out[str(it[name_key])] = it.get(value_key)
    return out


def _modified(items: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if isinstance(items, list):
        for it in items:
            if isinstance(it, dict) and "Name" in it:
                out[str(it["Name"])] = it.get("NewValue")
    return out


def _app_access_context(ad: dict[str, Any]) -> dict[str, Any]:
    aac = ad.get("AppAccessContext")
    if isinstance(aac, list):   # 1c-4: object or array accepted
        aac = aac[0] if aac and isinstance(aac[0], dict) else {}
    return aac if isinstance(aac, dict) else {}


def _truthy(v: Any) -> bool:
    return str(v).strip().lower() in ("true", "1", "$true", "yes")


def _split_list(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip()]
    return [p.strip() for p in _SPLIT.split(str(v)) if p.strip()]


def _strip_smtp(v: str) -> str:
    v = v.strip()
    return v[5:] if v.lower().startswith("smtp:") else v


def _client_app(info: str) -> str:
    """'Client=OWA;Action=ViaProxy' -> 'OWA'."""
    if not info:
        return ""
    for part in info.split(";"):
        if part.strip().lower().startswith("client="):
            return part.split("=", 1)[1].strip()
    return info[:40]


class UnrecognisedRecord(ValueError):
    pass


def normalize_auditdata(ad: dict[str, Any], wrapper: dict[str, Any] | None = None) -> Event:
    """Map one AuditData object (plus optional export-wrapper columns) onto an Event."""
    if not isinstance(ad, dict):
        raise UnrecognisedRecord("AuditData is not a JSON object")
    wrapper = wrapper or {}
    operation = str(ad.get("Operation") or wrapper.get("Operations") or wrapper.get("Operation") or "")
    if not operation:
        raise UnrecognisedRecord("record has no Operation")
    rt = record_type_int(ad.get("RecordType", wrapper.get("RecordType")))
    ev = Event()
    # when (1c-2: CreationTime is UTC; the wrapper CreationDate is kept only as a fallback)
    ct = ad.get("CreationTime")
    try:
        if ct:
            ev.ts_utc, ev.ts_note = parse_ts(str(ct), naive_zone="utc")
            ev.ts_original = str(ct)
        else:
            cd = wrapper.get("CreationDate")
            ev.ts_utc, note = parse_ts(str(cd), naive_zone="unknown")
            ev.ts_original = str(cd)
            ev.ts_note = "AuditData has no CreationTime; used the export's CreationDate: " + note
    except TimeParseError as exc:
        raise UnrecognisedRecord(f"bad timestamp: {exc}") from exc
    ev.record_id = str(ad.get("Id") or wrapper.get("Identity") or wrapper.get("RecordId") or "")
    ev.operation = operation
    key = op_key(operation)
    cat_act = OPERATIONS.get(key)
    ev.source = SOURCE_BY_RECORD_TYPE.get(rt or -1, "ual_other")
    if cat_act is None:
        ev.category, ev.action = "other", "other"
    else:
        ev.category, ev.action = cat_act
    ev.actor = str(ad.get("UserId") or wrapper.get("UserIds") or wrapper.get("UserId") or "").strip().lower()
    ev.actor_id = str(ad.get("UserKey") or "")
    ip_raw = ad.get("ClientIP") or ad.get("ClientIPAddress") or ad.get("ActorIpAddress") or ""
    ev.ip = split_ip(ip_raw)
    aac = _app_access_context(ad)
    ev.session_id = str(aac.get("AADSessionId") or "")
    ev.token_id = str(aac.get("UniqueTokenId") or "")          # case-sensitive: never case-fold
    ev.app_id = str(aac.get("ClientAppId") or ad.get("ClientAppId") or ad.get("AppId") or ad.get("ApplicationId") or "")
    status = str(ad.get("ResultStatus") or "").lower()
    ev.outcome = {"succeeded": "success", "success": "success", "true": "success", "partiallysucceeded": "success",
                  "failed": "failure", "false": "failure"}.get(status, "unknown")
    det: dict[str, Any] = {"record_type": rt, "record_type_name": RECORD_TYPES.get(rt or -1, str(ad.get("RecordType"))),
                           "workload": ad.get("Workload", "")}
    if ip_raw and str(ip_raw) != ev.ip:
        det["ip_raw"] = str(ip_raw)
    if aac.get("IssuedAtTime"):
        det["token_issued_at"] = aac.get("IssuedAtTime")
    ev.details = det

    if rt == 1 or "Parameters" in ad:
        _exchange_admin(ad, ev)
    elif rt in (2, 3, 19, 50) or ad.get("MailboxOwnerUPN"):
        _exchange_mailbox(ad, ev)
    elif rt in (4, 6, 7, 14, 36):
        _sharepoint(ad, ev)
    elif rt in (9, 15):
        _sts_logon(ad, ev)
    elif rt == 8:
        _directory(ad, ev)
    if ev.category == "other":
        det["unmapped_operation"] = True
    if ev.target:
        ev.target = ev.target.lower() if "@" in ev.target else ev.target
    return ev


def _exchange_admin(ad: dict[str, Any], ev: Event) -> None:
    params = _nv(ad.get("Parameters"))
    lower = {k.lower(): v for k, v in params.items()}
    d = ev.details
    d["parameters"] = params
    d["object_id"] = ad.get("ObjectId", "")
    d["client_info"] = ad.get("ClientInfoString", "") or ""
    if d["client_info"]:
        ev.client_app = _client_app(d["client_info"])
    if ad.get("ExternalAccess") not in (None, False, "False", "false"):
        d["external_access"] = True
    if ev.category == "mail_rule":
        name = lower.get("name")
        if not name:
            obj = str(ad.get("ObjectId") or lower.get("identity") or "")
            name = obj.rsplit("\\", 1)[-1] if obj else ""
        d["rule_name"] = name or ""
        fwd = []
        for k in ("forwardto", "redirectto", "forwardasattachmentto"):
            fwd.extend(_strip_smtp(x) for x in _split_list(lower.get(k)))
        if fwd:
            d["forward_to"] = ";".join(fwd)
        for k in ("deletemessage", "softdeletemessage", "permanentdelete"):
            if _truthy(lower.get(k)):
                d["delete_message"] = True
        if lower.get("movetofolder"):
            d["move_to_folder"] = str(lower["movetofolder"])
        if lower.get("copytofolder"):
            d["copy_to_folder"] = str(lower["copytofolder"])
        if lower.get("markasread") is not None:
            d["mark_as_read"] = _truthy(lower.get("markasread"))
        words = []
        for k in ("subjectcontainswords", "subjectorbodycontainswords", "bodycontainswords", "fromaddresscontainswords"):
            words.extend(_split_list(lower.get(k)))
        if words:
            d["keywords"] = words
        if lower.get("from"):
            d["from_filter"] = str(lower["from"])
        if lower.get("stopprocessingrules") is not None:
            d["stop_processing"] = _truthy(lower.get("stopprocessingrules"))
        mbx = str(lower.get("mailbox") or "")
        ident = str(lower.get("identity") or "")
        ev.target = mbx if "@" in mbx else (ident.split("\\")[0] if "@" in ident.split("\\")[0] else ev.actor)
    elif ev.category == "mailbox_config":
        ident = str(lower.get("identity") or ad.get("ObjectId") or "")
        mailbox = ident.split(":")[0] if ":\\" in ident or ident.count(":") == 1 else ident
        ev.target = mailbox
        if ev.action == "mailbox.update":
            fwd_keys = [k for k in ("forwardingsmtpaddress", "forwardingaddress") if k in lower]
            if fwd_keys:
                vals = [_strip_smtp(str(lower[k])) for k in fwd_keys if lower[k] not in (None, "", "$null")]
                if vals:
                    ev.action = "mailbox.forwarding_set"
                    d["forward_to"] = ";".join(vals)
                else:
                    ev.action = "mailbox.forwarding_cleared"
                if "delivertomailboxandforward" in lower:
                    d["deliver_and_forward"] = _truthy(lower["delivertomailboxandforward"])
            elif lower.get("grantsendonbehalfto"):
                ev.action = "mailbox.send_on_behalf_add"
                d["grantee"] = str(lower["grantsendonbehalfto"])
        if "user" in lower or "trustee" in lower:
            d["grantee"] = str(lower.get("user") or lower.get("trustee"))
        if "accessrights" in lower:
            d["access_rights"] = str(lower["accessrights"])
        if ":\\" in ident:
            d["folder"] = ident.split(":", 1)[1]


def _exchange_mailbox(ad: dict[str, Any], ev: Event) -> None:
    d = ev.details
    owner = str(ad.get("MailboxOwnerUPN") or "").lower()
    d["mailbox_owner"] = owner
    ev.target = owner or ev.actor
    info = str(ad.get("ClientInfoString") or "")
    d["client_info"] = info
    ev.client_app = _client_app(info)
    if ad.get("SessionId"):
        d["exchange_session_id"] = str(ad["SessionId"])  # not the Entra session (section 3: unconfirmed)
    d["logon_type"] = ad.get("LogonType")
    props = _nv(ad.get("OperationProperties"))
    if props.get("MailAccessType"):
        d["access_type"] = props["MailAccessType"]
    if props.get("IsThrottled") is not None:
        d["is_throttled"] = _truthy(props.get("IsThrottled"))
    folders = ad.get("Folders") or []
    paths, items = [], 0
    if isinstance(folders, list):
        for f in folders:
            if isinstance(f, dict):
                if f.get("Path"):
                    paths.append(f["Path"])
                fi = f.get("FolderItems") or []
                items += len(fi) if isinstance(fi, list) else 0
    if ev.action == "mail.items_accessed":
        d["folders"] = paths
        d["item_count"] = items or int(ad.get("OperationCount") or 0)
        d["operation_count"] = ad.get("OperationCount")
    item = ad.get("Item")
    if isinstance(item, dict):
        d["subject"] = item.get("Subject", "")
        pf = item.get("ParentFolder") or {}
        d["folder"] = pf.get("Path", "") if isinstance(pf, dict) else ""
    if ad.get("recipientList"):
        d["recipients"] = ";".join(_split_list(ad.get("recipientList")))
    if isinstance(ad.get("AffectedItems"), list):
        d["item_count"] = len(ad["AffectedItems"])
        fol = ad.get("Folder") or {}
        d["folder"] = fol.get("Path", "") if isinstance(fol, dict) else ""
    if ev.category == "mail_rule":  # UpdateInboxRules (1d-4: fields unconfirmed)
        d["rule_name"] = str(props.get("RuleName") or "")
        actions = str(props.get("RuleActions") or "")
        if actions:
            d["rule_actions"] = actions
            la = actions.lower()
            if "delete" in la:
                d["delete_message"] = True
            if "forward" in la or "redirect" in la:
                d["forward_to"] = ";".join(re.findall(r"[\w.+-]+@[\w.-]+", actions)) or "unknown"
            if "markasread" in la or "mark as read" in la:
                d["mark_as_read"] = True
            m = re.search(r"MoveToFolder[^A-Za-z0-9]*([^;,]*)", actions)
            if m:
                d["move_to_folder"] = m.group(1).strip()
    if ev.category == "mailbox_config":
        for k in ("MemberUpn",):
            if ad.get(k):
                d["grantee"] = ad[k]


def _sharepoint(ad: dict[str, Any], ev: Event) -> None:
    d = ev.details
    ev.user_agent = str(ad.get("UserAgent") or "")
    d["file_name"] = ad.get("SourceFileName", "")
    d["site_url"] = ad.get("SiteUrl", "")
    d["relative_url"] = ad.get("SourceRelativeUrl", "")
    d["item_type"] = ad.get("ItemType", "")
    d["event_source"] = ad.get("EventSource", "")
    ev.target = str(ad.get("ObjectId") or "")
    if ad.get("TargetUserOrGroupName"):
        d["share_target"] = str(ad["TargetUserOrGroupName"])
        d["share_target_type"] = str(ad.get("TargetUserOrGroupType") or "")
    if ad.get("EventData"):
        d["event_data"] = str(ad["EventData"])[:200]


def _sts_logon(ad: dict[str, Any], ev: Event) -> None:
    d = ev.details
    ext = _nv(ad.get("ExtendedProperties"))
    devp = _nv(ad.get("DeviceProperties"))
    ev.user_agent = str(ext.get("UserAgent") or "")
    ev.app_id = str(ad.get("ApplicationId") or ev.app_id)
    code = ad.get("ErrorNumber", ad.get("ErrorCode"))   # 1g-2: both spellings seen
    if code is not None and str(code).strip() != "":
        ev.status_code = str(code)
        ev.outcome = "success" if str(code).strip() == "0" else "failure"
    elif op_key(ev.operation) == "userloginfailed":
        ev.outcome = "failure"
    elif op_key(ev.operation) == "userloggedin":
        ev.outcome = "success"
    if ad.get("LogonError"):
        d["logon_error"] = ad["LogonError"]
    d["request_type"] = ext.get("RequestType", "")
    d["result_status_detail"] = ext.get("ResultStatusDetail", "")
    if devp.get("SessionId"):
        d["device_session_id"] = devp["SessionId"]   # equality with Entra sessionId unconfirmed
    for k in ("OS", "BrowserType"):
        if devp.get(k):
            d[k.lower()] = devp[k]
    ev.correlation_id = str(ad.get("InterSystemsId") or "")
    ev.request_id = str(ad.get("IntraSystemId") or ad.get("IntraSystemsId") or "")
    ev.resource = str(ad.get("ObjectId") or "")


def _directory(ad: dict[str, Any], ev: Event) -> None:
    d = ev.details
    mod = _modified(ad.get("ModifiedProperties"))
    ext = _nv(ad.get("ExtendedProperties"))
    targets = ad.get("Target") or []
    ua = ""
    add = ext.get("additionalDetails")
    if add:
        m = re.search(r'"User-Agent"\s*:\s*"([^"]*)"', str(add))
        if m:
            ua = m.group(1)
    ev.user_agent = ua
    if ev.action in ("app.consent", "app.permission_grant", "app.role_grant", "app.service_principal_add"):
        perms = str(mod.get("ConsentAction.Permissions") or mod.get("DelegatedPermissionGrant.Scope") or "")
        scopes: list[str] = []
        for m in _SCOPE.finditer(perms):
            scopes.extend(s for s in m.group(1).split() if s)
        if not scopes and mod.get("DelegatedPermissionGrant.Scope"):
            scopes = str(mod["DelegatedPermissionGrant.Scope"]).split()
        d["scopes"] = sorted(set(scopes))
        if "ConsentContext.IsAdminConsent" in mod:
            d["is_admin_consent"] = _truthy(str(mod["ConsentContext.IsAdminConsent"]).strip('"'))
        if "ConsentContext.OnBehalfOfAll" in mod:
            d["on_behalf_of_all"] = _truthy(str(mod["ConsentContext.OnBehalfOfAll"]).strip('"'))
        spn = str(mod.get("TargetId.ServicePrincipalNames") or "")
        app_ids = _GUID.findall(spn)
        names = [t.get("ID") for t in targets if isinstance(t, dict) and t.get("Type") == 1]
        if names:
            d["app_name"] = names[0]
        if app_ids:
            ev.app_id = app_ids[0].lower()
            d["app_id"] = ev.app_id
        else:
            ev.app_id = ""
        ev.target = d.get("app_name") or str(ad.get("ObjectId") or "")
    elif ev.category in ("auth_method", "directory", "device"):
        upns = [t.get("ID") for t in targets if isinstance(t, dict) and "@" in str(t.get("ID"))]
        ev.target = (upns[0] if upns else str(ad.get("ObjectId") or "")).lower() if upns else str(ad.get("ObjectId") or "")
        if ev.category == "auth_method":
            d["method"] = str(ext.get("Method") or ext.get("AdditionalInfo") or mod.get("StrongAuthenticationMethod") or "")
        if ev.action == "directory.user_update":
            changed = [k for k in mod if "StrongAuthentication" in k]
            if changed:
                ev.category, ev.action = "auth_method", "auth.strong_auth_update"
                d["method"] = ", ".join(changed)
        if ev.category == "device":
            names = [t.get("ID") for t in targets if isinstance(t, dict) and t.get("Type") == 1]
            dn = mod.get("DisplayName")
            if isinstance(dn, str) and dn.startswith("["):
                dn = dn.strip('[]"')
            d["device_name"] = (names[0] if names else dn) or ""
            ev.device_name = d["device_name"]
    ev.correlation_id = str(ad.get("InterSystemsId") or "")
    if ev.outcome == "unknown":
        ev.outcome = "success"
