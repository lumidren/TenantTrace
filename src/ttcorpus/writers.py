"""Render simulated activities into Microsoft 365 export layouts.

Every layout here is transcribed from docs/sources/microsoft-formats.md (section numbers in
the comments). Where Microsoft does not document a layout the writer follows the
"best knowledge" listed there and the layout is marked unverified in docs/VERIFY.md.
This module is written independently of TenantTrace's parsers and must not import them.
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ttcorpus.engine import RT, World
from ttcorpus.model import AuditOp, SignIn
from ttcorpus.output import write_csv, write_json_array

RT_NAME = {v: k for k, v in RT.items()}

# 1a-1 (CONFIRMED): four-column Purview export.
PURVIEW_COLUMNS = ["CreationDate", "UserIds", "Operations", "AuditData"]
# 1a-2 (UNCONFIRMED best knowledge): newer Purview export.
PURVIEW_V2_COLUMNS = ["RecordId", "CreationDate", "RecordType", "Operation", "UserId", "AuditData",
                      "AssociatedAdminUnits", "AssociatedAdminUnitsNames"]
# 1b-1 (PARTIAL): Search-UnifiedAuditLog | Export-Csv. Order not documented.
PS_UAL_COLUMNS = ["RunspaceId", "RecordType", "CreationDate", "UserIds", "Operations", "AuditData",
                  "ResultIndex", "ResultCount", "Identity", "IsValid", "ObjectState"]
# 2a-2 (UNCONFIRMED best knowledge): Entra admin-centre sign-in CSV header.
ENTRA_CSV_COLUMNS = [
    "Date (UTC)", "Request ID", "User agent", "Correlation ID", "User ID", "User", "Username", "User type",
    "Cross tenant access type", "Incoming token type", "Authentication Protocol", "Unique token identifier",
    "Original transfer method", "Client credential type", "Token issuer type", "Token issuer name", "Latency",
    "Application", "Application ID", "Resource", "Resource ID", "Resource tenant ID", "Home tenant ID",
    "Home tenant name", "IP address", "Location", "Status", "Sign-in error code", "Failure reason", "Client app",
    "Device ID", "Browser", "Operating System", "Compliant", "Managed", "Join Type",
    "Multifactor authentication result", "Multifactor authentication auth method",
    "Multifactor authentication auth detail", "Authentication requirement", "Sign-in identifier", "Session ID",
    "IP address (seen by resource)", "Through Global Secure Access", "Global Secure Access IP address",
    "Autonomous system number", "Flagged for review", "Token Protection - Sign In Session", "Conditional Access",
    "Managed Identity type", "Associated Resource Id", "Federated Token Id", "Federated Token Issuer",
]


# ----------------------------------------------------------------------------- time formats

def ual_creation_time(t: datetime) -> str:
    """1c-2: AuditData.CreationTime is UTC; Microsoft's samples show no offset and no fraction."""
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def purview_creation_date(t: datetime) -> str:
    """1a-3 (UNCONFIRMED): ISO 8601 UTC with seven fractional digits and Z."""
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond:06d}0Z"


def ps_creation_date(t: datetime) -> str:
    """1b-1 (UNCONFIRMED): DateTime written in the en-US culture, e.g. 11/17/2025 2:30:15 PM."""
    t = t.astimezone(timezone.utc)
    hour = t.hour % 12 or 12
    return f"{t.month}/{t.day}/{t.year} {hour}:{t.minute:02d}:{t.second:02d} {'AM' if t.hour < 12 else 'PM'}"


def graph_time(t: datetime) -> str:
    """2b-5 (CONFIRMED): createdDateTime is ISO 8601 UTC with Z."""
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ----------------------------------------------------------------------------- AuditData

def _app_access_context(op: AuditOp, w: World) -> dict[str, Any] | None:
    if not op.session_id and not op.token_id:
        return None
    ctx: dict[str, Any] = {}
    if op.session_id:
        ctx["AADSessionId"] = op.session_id
    if op.token_id:
        ctx["UniqueTokenId"] = op.token_id
    if op.app_id:
        ctx["ClientAppId"] = op.app_id
    ctx["IssuedAtTime"] = ual_creation_time(op.t - timedelta(minutes=5))
    return ctx


def audit_data(op: AuditOp, w: World) -> dict[str, Any]:
    u = op.user
    d: dict[str, Any] = {
        "CreationTime": ual_creation_time(op.t),
        "Id": op.record_id,
        "Operation": op.operation,
        "OrganizationId": w.tenant_id,
        "RecordType": op.record_type,
        "ResultStatus": op.result_status,
        "UserKey": u.object_id,
        "UserType": 0,
        "Version": 1,
        "Workload": op.workload,
        "UserId": u.upn,
    }
    rt = op.record_type
    p = op.payload
    aac = _app_access_context(op, w)
    if rt == RT["ExchangeAdmin"]:
        d.update({
            "ClientIP": op.ip,
            "ObjectId": p.get("ObjectId", ""),
            "Parameters": p.get("Parameters", []),
            "ExternalAccess": False,
            "OrganizationName": w.domain,
            "OriginatingServer": "HL0PR01MB4421 (15.20.8000.010)",
            "ResultStatus": "True",
        })
        if aac:
            d["AppAccessContext"] = aac
    elif rt == RT["ExchangeItemAggregated"]:
        owner = p.get("MailboxOwnerUPN", u.upn)
        folders = []
        for f in p.get("Folders", []):
            folders.append({
                "Id": _hexid(w),
                "Path": f["FolderPath"],
                "FolderItems": [{"Id": _hexid(w), "InternetMessageId": it["InternetMessageId"],
                                 "SizeInBytes": it["SizeInBytes"]} for it in f["Items"]],
            })
        d.update({
            "ClientIP": op.ip,
            "ObjectId": "",
            "AppId": op.app_id,
            "ClientAppId": op.app_id,
            "ClientIPAddress": op.ip,
            "ClientInfoString": p.get("ClientInfoString", ""),
            "ExternalAccess": False,
            "InternalLogonType": 0,
            "LogonType": 0,
            "LogonUserSid": "S-1-5-21-" + str(abs(hash(u.upn)) % 10**9),
            "MailboxGuid": _guid_for(w, "mbx:" + owner),
            "MailboxOwnerSid": "S-1-5-21-" + str(abs(hash(owner)) % 10**9),
            "MailboxOwnerUPN": owner,
            "OperationProperties": [{"Name": "MailAccessType", "Value": p.get("MailAccessType", "Bind")}],
            "OperationCount": p.get("OperationCount", 1),
            "OrganizationName": w.domain,
            "OriginatingServer": "HL0PR01MB4421 (15.20.8000.010)",
            "SessionId": _guid_for(w, "exsession:" + (op.session_id or op.ip)),
            "Folders": folders,
            "ResultStatus": "Succeeded",
        })
        # Section 3 caveat: identifiers are missing on some aggregated Exchange entries.
        if aac and not (p.get("MailAccessType") == "Sync" and w.ids.rng.random() < 0.3):
            d["AppAccessContext"] = aac
    elif rt in (RT["ExchangeItem"], RT["ExchangeItemGroup"]):
        owner = p.get("MailboxOwnerUPN", u.upn)
        d.update({
            "ClientIP": op.ip,
            "ObjectId": "",
            "ClientIPAddress": op.ip,
            "ClientInfoString": p.get("ClientInfoString", ""),
            "ExternalAccess": False,
            "InternalLogonType": 0,
            "LogonType": 0,
            "MailboxGuid": _guid_for(w, "mbx:" + owner),
            "MailboxOwnerUPN": owner,
            "OrganizationName": w.domain,
            "OriginatingServer": "HL0PR01MB4421 (15.20.8000.010)",
            "SessionId": _guid_for(w, "exsession:" + (op.session_id or op.ip)),
            "ResultStatus": "Succeeded",
        })
        if op.operation in ("Send", "SendAs", "SendOnBehalf"):
            d["Item"] = {"Id": _hexid(w), "Subject": p.get("Subject", ""),
                         "ParentFolder": {"Id": _hexid(w), "Path": "\\Sent Items"},
                         "InternetMessageId": f"<{w.ids.token(16)}@{w.domain}>",
                         "SizeInBytes": w.ids.rng.randint(3000, 40000)}
            d["SaveToSentItems"] = True
            if p.get("recipient"):
                d["recipientCount"] = 1
                d["recipientList"] = [p["recipient"]]
        else:
            n = int(p.get("count", 1))
            d["Folder"] = {"Id": _hexid(w), "Path": p.get("folder", "\\Inbox")}
            d["AffectedItems"] = [{"Id": _hexid(w), "Subject": "Re: remittance",
                                   "ParentFolder": {"Id": _hexid(w), "Path": p.get("folder", "\\Inbox")},
                                   "InternetMessageId": f"<{w.ids.token(16)}@{w.domain}>"} for _ in range(n)]
        if aac:
            d["AppAccessContext"] = aac
    elif rt in (RT["SharePointFileOperation"], RT["SharePointSharingOperation"], RT["SharePoint"]):
        d.update({
            "ClientIP": op.ip,
            "ObjectId": p.get("ObjectId", ""),
            "Site": _guid_for(w, "site:" + p.get("SiteUrl", "")),
            "ItemType": p.get("ItemType", "File"),
            "EventSource": p.get("EventSource", "SharePoint"),
            "UserAgent": op.user_agent,
            "SiteUrl": p.get("SiteUrl", ""),
            "SourceRelativeUrl": p.get("SourceRelativeUrl", ""),
            "SourceFileName": p.get("SourceFileName", ""),
            "SourceFileExtension": p.get("SourceFileExtension", ""),
            "ListItemUniqueId": p.get("ListItemUniqueId", ""),
            "ApplicationId": op.app_id,
        })
        if rt == RT["SharePointSharingOperation"]:
            d["TargetUserOrGroupName"] = p.get("TargetUserOrGroupName", "")
            d["TargetUserOrGroupType"] = p.get("TargetUserOrGroupType", "")
            d["UniqueSharingId"] = _guid_for(w, "share:" + op.record_id)
            d["EventData"] = "<Type>View</Type>" if op.operation == "AnonymousLinkCreated" else "<Type>Edit</Type>"
            if not d["TargetUserOrGroupName"]:
                del d["TargetUserOrGroupName"], d["TargetUserOrGroupType"]
        if aac:
            d["AppAccessContext"] = aac
    elif rt == RT["AzureActiveDirectoryStsLogon"]:
        # 1g-1 / 1g-2: ClientIP is not logged for Entra events; ActorIpAddress carries the IP.
        ok = op.result_status == "Success"
        d.update({
            "ObjectId": p.get("object_id", ""),
            "AzureActiveDirectoryEventType": 0,
            "ActorIpAddress": op.ip,
            "Actor": [{"ID": u.object_id, "Type": 0}, {"ID": u.upn, "Type": 5}],
            "ActorContextId": w.tenant_id,
            "ApplicationId": p.get("application_id", op.app_id),
            "InterSystemsId": p.get("correlation_id", ""),
            "IntraSystemId": p.get("mirror_of", ""),
            "Target": [{"ID": p.get("object_id", ""), "Type": 0}],
            "TargetContextId": w.tenant_id,
            "ErrorNumber": str(p.get("error_code", 0)),
            "LogonError": "" if ok else "InvalidUserNameOrPassword",
            "ExtendedProperties": [
                {"Name": "ResultStatusDetail", "Value": "Success" if ok else "UserError"},
                {"Name": "UserAgent", "Value": op.user_agent},
                {"Name": "RequestType", "Value": "OAuth2:Authorize"},
            ],
            "DeviceProperties": [{"Name": "SessionId", "Value": op.session_id}] if op.session_id else [],
            "ModifiedProperties": [],
        })
    elif rt == RT["AzureActiveDirectory"]:
        d.update({
            "AzureActiveDirectoryEventType": 1,
            "ActorIpAddress": op.ip,
            "Actor": [{"ID": u.upn, "Type": 5}, {"ID": u.object_id, "Type": 2}],
            "ActorContextId": w.tenant_id,
            "InterSystemsId": _guid_for(w, "corr:" + op.record_id),
            "IntraSystemId": _guid_for(w, "intra:" + op.record_id),
            "TargetContextId": w.tenant_id,
            "ExtendedProperties": [{"Name": "additionalDetails", "Value": json.dumps({"User-Agent": op.user_agent})}],
        })
        if op.operation == "Consent to application.":
            spid = _guid_for(w, "sp:" + p["app_id"])
            scopes = " ".join(p.get("scopes", []))
            d["ObjectId"] = spid
            d["Target"] = [{"ID": "ServicePrincipal_" + spid, "Type": 2}, {"ID": p["app_name"], "Type": 1},
                           {"ID": spid, "Type": 2}]
            d["ModifiedProperties"] = [
                {"Name": "ConsentContext.IsAdminConsent", "NewValue": str(p.get("is_admin_consent", False)), "OldValue": ""},
                {"Name": "ConsentContext.IsAppOnly", "NewValue": "False", "OldValue": ""},
                {"Name": "ConsentContext.OnBehalfOfAll", "NewValue": str(p.get("on_behalf_of_all", False)), "OldValue": ""},
                {"Name": "ConsentAction.Permissions",
                 "NewValue": f"[] => [[Id: {w.ids.token(30)}, ClientId: {spid}, PrincipalId: {u.object_id}, "
                             f"ResourceId: {_guid_for(w, 'graph-sp')}, ConsentType: Principal, Scope: {scopes}, "
                             f"CreatedDateTime: , LastModifiedDateTime ]]; ",
                 "OldValue": ""},
                {"Name": "TargetId.ServicePrincipalNames", "NewValue": p["app_id"], "OldValue": ""},
            ]
        elif op.operation.startswith("User ") and "security info" in op.operation:
            d["ObjectId"] = u.upn
            d["Target"] = [{"ID": "User_" + u.object_id, "Type": 2}, {"ID": u.upn, "Type": 5}]
            d["ModifiedProperties"] = []
            d["ExtendedProperties"].append({"Name": "AdditionalInfo", "Value": p.get("detail", "")})
            d["ExtendedProperties"].append({"Name": "Method", "Value": p.get("method", "")})
        elif op.operation == "Register device.":
            dev = _guid_for(w, "dev:" + p.get("device_name", ""))
            d["ObjectId"] = dev
            d["Target"] = [{"ID": "Device_" + dev, "Type": 2}, {"ID": p.get("device_name", ""), "Type": 1}]
            d["ModifiedProperties"] = [
                {"Name": "DisplayName", "NewValue": json.dumps([p.get("device_name", "")]), "OldValue": "[]"},
                {"Name": "DeviceOSType", "NewValue": json.dumps([p.get("os", "")]), "OldValue": "[]"},
            ]
        else:
            d["ObjectId"] = u.upn
            d["Target"] = [{"ID": u.upn, "Type": 5}]
            d["ModifiedProperties"] = []
        if aac:
            d["AppAccessContext"] = aac
    return d


def _guid_for(w: World, key: str) -> str:
    import uuid as _uuid

    return str(_uuid.uuid5(_uuid.NAMESPACE_URL, f"{w.tenant_id}/{key}"))


def _hexid(w: World) -> str:
    return "".join(w.ids.rng.choice("0123456789ABCDEF") for _ in range(40))


# ----------------------------------------------------------------------------- UAL writers

def _ual_ops(w: World) -> list[AuditOp]:
    return list(w.ops)


def write_purview_csv(w: World, ops: list[AuditOp], path: Path, v2: bool = False) -> int:
    rows = []
    for op in ops:
        ad = audit_data(op, w)
        aj = json.dumps(ad, ensure_ascii=False, separators=(",", ":"))
        if v2:
            rows.append([op.record_id, purview_creation_date(op.t), RT_NAME.get(op.record_type, op.record_type),
                         op.operation, op.user.upn, aj, "", ""])
        else:
            rows.append([purview_creation_date(op.t), op.user.upn, op.operation, aj])
    # newest first, as the portal lists results
    rows.reverse()
    return write_csv(path, PURVIEW_V2_COLUMNS if v2 else PURVIEW_COLUMNS, rows, encoding="utf-8-sig")


def write_ps_csv(w: World, ops: list[AuditOp], path: Path, encoding: str = "utf-16-le",
                 result_count: int | None = None, type_line: bool = False) -> int:
    rng = random.Random(len(ops))
    order = list(ops)
    rng.shuffle(order)  # 1b-3: ReturnLargeSet output is unsorted
    total = result_count if result_count is not None else len(order)
    runspace = _guid_for(w, "runspace")
    rows = []
    for i, op in enumerate(order, 1):
        ad = audit_data(op, w)
        rows.append([runspace, RT_NAME.get(op.record_type, str(op.record_type)), ps_creation_date(op.t), op.user.upn,
                     op.operation, json.dumps(ad, ensure_ascii=False, separators=(",", ":")), str(i), str(total),
                     op.record_id, "True", "New"])
    pre = "#TYPE Deserialized.Microsoft.Exchange.Management.SystemConfigurationTasks.AuditRecord" if type_line else None
    return write_csv(path, PS_UAL_COLUMNS, rows, encoding=encoding, preamble=pre)


# ----------------------------------------------------------------------------- Entra sign-ins

def _yes_no(b: bool) -> str:
    return "Yes" if b else "No"


def _mfa_method(s: SignIn) -> str:
    if s.mfa_detail == "MFA completed in Azure AD":
        return "Mobile app notification"
    return ""


def write_entra_csv(w: World, signins: list[SignIn], path: Path) -> int:
    rows = []
    for s in sorted(signins, key=lambda x: x.t, reverse=True):
        dev = s.device
        status = "Success" if s.success else "Failure"
        loc = ", ".join([s.loc.city, s.loc.state, s.loc.country])
        row = {
            "Date (UTC)": graph_time(s.t),
            "Request ID": s.request_id,
            "User agent": dev.user_agent,
            "Correlation ID": s.correlation_id,
            "User ID": s.user.object_id,
            "User": s.user.display,
            "Username": s.user.upn,
            "User type": "Member",
            "Cross tenant access type": "None",
            "Incoming token type": "None" if s.interactive else "Primary Refresh Token",
            "Authentication Protocol": s.auth_protocol if s.auth_protocol != "none" else "None",
            "Unique token identifier": s.token_id,
            "Original transfer method": "None",
            "Client credential type": "None",
            "Token issuer type": "AzureAD",
            "Token issuer name": "",
            "Latency": str(w.ids.rng.randint(40, 900)),
            "Application": s.app.name,
            "Application ID": s.app.app_id,
            "Resource": s.resource.name,
            "Resource ID": s.resource.app_id,
            "Resource tenant ID": w.tenant_id,
            "Home tenant ID": w.tenant_id,
            "Home tenant name": "",
            "IP address": s.ip,
            "Location": loc,
            "Status": status,
            "Sign-in error code": str(s.error_code),
            "Failure reason": s.failure_reason or ("Other." if not s.success else ""),
            "Client app": s.client_app,
            "Device ID": dev.device_id,
            "Browser": dev.browser,
            "Operating System": dev.os,
            "Compliant": _yes_no(dev.compliant),
            "Managed": _yes_no(dev.managed),
            "Join Type": dev.trust_type,
            "Multifactor authentication result": s.mfa_detail,
            "Multifactor authentication auth method": _mfa_method(s),
            "Multifactor authentication auth detail": "",
            "Authentication requirement": s.auth_requirement,
            "Sign-in identifier": s.user.upn,
            "Session ID": s.session_id,
            "IP address (seen by resource)": s.ip,
            "Through Global Secure Access": "No",
            "Global Secure Access IP address": "",
            "Autonomous system number": "",
            "Flagged for review": "No",
            "Token Protection - Sign In Session": "Unbound",
            "Conditional Access": "Not Applied",
            "Managed Identity type": "",
            "Associated Resource Id": "",
            "Federated Token Id": "",
            "Federated Token Issuer": "",
        }
        rows.append([row[c] for c in ENTRA_CSV_COLUMNS])
    return write_csv(path, ENTRA_CSV_COLUMNS, rows, encoding="utf-8-sig")


def signin_json(w: World, s: SignIn) -> dict[str, Any]:
    """2b-3 / 2b-4: Graph beta signIn shape (the JSON download layout is UNCONFIRMED)."""
    dev = s.device
    return {
        "id": s.request_id,
        "createdDateTime": graph_time(s.t),
        "userDisplayName": s.user.display,
        "userPrincipalName": s.user.upn,
        "userId": s.user.object_id,
        "appId": s.app.app_id,
        "appDisplayName": s.app.name,
        "ipAddress": s.ip,
        "clientAppUsed": s.client_app,
        "userAgent": dev.user_agent,
        "correlationId": s.correlation_id,
        "conditionalAccessStatus": "notApplied",
        "isInteractive": s.interactive,
        "signInEventTypes": ["interactiveUser" if s.interactive else "nonInteractiveUser"],
        "riskDetail": "none",
        "riskLevelAggregated": "none",
        "riskLevelDuringSignIn": "none",
        "riskState": "none",
        "resourceDisplayName": s.resource.name,
        "resourceId": s.resource.app_id,
        "authenticationRequirement": s.auth_requirement,
        "authenticationProtocol": s.auth_protocol,
        "incomingTokenType": "none" if s.interactive else "primaryRefreshToken",
        "uniqueTokenIdentifier": s.token_id,
        "sessionId": s.session_id,
        "status": {"errorCode": s.error_code, "failureReason": s.failure_reason or ("Other." if not s.success else ""),
                   "additionalDetails": s.mfa_detail or None},
        "deviceDetail": {"deviceId": dev.device_id, "displayName": dev.display_name, "operatingSystem": dev.os,
                         "browser": dev.browser, "isCompliant": dev.compliant, "isManaged": dev.managed,
                         "trustType": dev.trust_type},
        "location": {"city": s.loc.city, "state": s.loc.state, "countryOrRegion": s.loc.country,
                     "geoCoordinates": {"altitude": None, "latitude": s.loc.lat, "longitude": s.loc.lon}},
        "mfaDetail": {"authMethod": _mfa_method(s) or None, "authDetail": None},
        "authenticationDetails": [],
        "appliedConditionalAccessPolicies": [],
    }


def write_entra_json(w: World, signins: list[SignIn], path: Path) -> int:
    items = [signin_json(w, s) for s in sorted(signins, key=lambda x: x.t, reverse=True)]
    return write_json_array(path, items, indent=2)
