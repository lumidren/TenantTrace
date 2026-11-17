"""Normalize Microsoft Entra sign-in records into events.

Three shapes are handled (docs/sources/microsoft-formats.md section 2):
  * Graph `signIn` objects (beta and v1.0 property names), as in the admin-centre JSON download
    and collector output;
  * the Azure Monitor diagnostic envelope (`category` + `properties`), as exported from Log
    Analytics or streamed to a SIEM;
  * rows of the admin-centre CSV download, matched by header name case-insensitively.
"""

from __future__ import annotations

from typing import Any

from tenanttrace.ingest.timeparse import TimeParseError, parse_ts
from tenanttrace.schema import Event

SOURCE_INTERACTIVE = "entra_signin_interactive"
SOURCE_NONINTERACTIVE = "entra_signin_noninteractive"


class UnrecognisedSignIn(ValueError):
    pass


def _bool(v: Any) -> bool | None:
    if isinstance(v, bool):
        return v
    if v is None:
        return None
    s = str(v).strip().lower()
    if s in ("true", "yes", "1"):
        return True
    if s in ("false", "no", "0"):
        return False
    return None


def _yn(v: Any) -> str:
    b = _bool(v)
    return "" if b is None else ("true" if b else "false")


def _auth_req(v: Any) -> str:
    s = str(v or "").strip()
    low = s.lower().replace("-", "").replace(" ", "")
    if low in ("singlefactorauthentication", "singlefactor"):
        return "singleFactorAuthentication"
    if low in ("multifactorauthentication", "multifactor"):
        return "multiFactorAuthentication"
    return s


def _outcome(error_code: Any, status_text: str = "") -> tuple[str, str]:
    st = (status_text or "").strip().lower()
    code = "" if error_code is None else str(error_code).strip()
    if st in ("success", "failure", "interrupted"):
        return st, code
    if code == "":
        return "unknown", code
    return ("success" if code == "0" else "failure"), code


def interactive_from_record(rec: dict[str, Any]) -> bool | None:
    b = _bool(rec.get("isInteractive"))
    if b is not None:
        return b
    types = rec.get("signInEventTypes")
    if isinstance(types, list) and types:
        lt = [str(t).lower() for t in types]
        if "interactiveuser" in lt:
            return True
        if "noninteractiveuser" in lt:
            return False
    return None


def normalize_graph_signin(rec: dict[str, Any], interactive_hint: bool | None = None) -> Event:
    if not isinstance(rec, dict):
        raise UnrecognisedSignIn("sign-in record is not a JSON object")
    created = rec.get("createdDateTime")
    if not created:
        raise UnrecognisedSignIn("sign-in record has no createdDateTime")
    ev = Event()
    try:
        ev.ts_utc, ev.ts_note = parse_ts(str(created), naive_zone="utc")
    except TimeParseError as exc:
        raise UnrecognisedSignIn(f"bad createdDateTime: {exc}") from exc
    ev.ts_original = str(created)
    ev.category, ev.action, ev.operation = "signin", "signin", "Sign-in"
    ev.record_id = str(rec.get("id") or "")
    ev.request_id = ev.record_id
    ev.actor = str(rec.get("userPrincipalName") or "").strip().lower()
    ev.actor_id = str(rec.get("userId") or "")
    ev.actor_display = str(rec.get("userDisplayName") or "")
    ev.ip = str(rec.get("ipAddress") or "")
    ev.app_id = str(rec.get("appId") or "")
    ev.app_name = str(rec.get("appDisplayName") or "")
    ev.resource = str(rec.get("resourceDisplayName") or "")
    ev.client_app = str(rec.get("clientAppUsed") or "")
    ev.user_agent = str(rec.get("userAgent") or "")
    ev.correlation_id = str(rec.get("correlationId") or "")
    ev.session_id = str(rec.get("sessionId") or "")
    ev.token_id = str(rec.get("uniqueTokenIdentifier") or "")
    ev.auth_requirement = _auth_req(rec.get("authenticationRequirement"))
    status = rec.get("status") or {}
    if not isinstance(status, dict):
        status = {}
    ev.outcome, ev.status_code = _outcome(status.get("errorCode"))
    mfa = rec.get("mfaDetail") or {}
    details_text = str(status.get("additionalDetails") or "")
    ev.mfa_detail = details_text or (str(mfa.get("authDetail") or "") if isinstance(mfa, dict) else "")
    dev = rec.get("deviceDetail") or {}
    if isinstance(dev, dict):
        ev.device_id = str(dev.get("deviceId") or "")
        ev.device_name = str(dev.get("displayName") or "")
        ev.device_os = str(dev.get("operatingSystem") or "")
        ev.device_browser = str(dev.get("browser") or "")
        ev.device_compliant = _yn(dev.get("isCompliant"))
        ev.device_managed = _yn(dev.get("isManaged"))
    loc = rec.get("location") or {}
    if isinstance(loc, dict):
        ev.geo_city = str(loc.get("city") or "")
        ev.geo_region = str(loc.get("state") or "")
        ev.geo_country = str(loc.get("countryOrRegion") or "").upper()
        geo = loc.get("geoCoordinates") or {}
        if isinstance(geo, dict) and geo.get("latitude") is not None and geo.get("longitude") is not None:
            try:
                ev.geo_lat = float(geo["latitude"])
                ev.geo_lon = float(geo["longitude"])
            except (TypeError, ValueError):
                pass
        if ev.geo_country or ev.geo_lat is not None:
            ev.geo_source = "log"
    inter = interactive_from_record(rec)
    basis = "isInteractive / signInEventTypes field"
    if inter is None:
        inter = interactive_hint if interactive_hint is not None else True
        basis = "file name" if interactive_hint is not None else "default (no field or file-name hint)"
    ev.interactive = 1 if inter else 0
    ev.source = SOURCE_INTERACTIVE if inter else SOURCE_NONINTERACTIVE
    det: dict[str, Any] = {"interactive_basis": basis}
    for k in ("incomingTokenType", "authenticationProtocol", "conditionalAccessStatus", "riskLevelDuringSignIn",
              "riskState", "crossTenantAccessType", "trustType"):
        if rec.get(k):
            det[k] = rec[k]
    if isinstance(dev, dict) and dev.get("trustType"):
        det["trust_type"] = dev["trustType"]
    if status.get("failureReason"):
        det["failure_reason"] = status["failureReason"]
    if isinstance(mfa, dict) and mfa.get("authMethod"):
        det["mfa_method"] = mfa["authMethod"]
    ev.details = det
    return ev


def normalize_azure_monitor(rec: dict[str, Any]) -> Event:
    """Azure Monitor diagnostic-settings envelope: {time, category, properties{...}}."""
    props = rec.get("properties")
    if not isinstance(props, dict):
        raise UnrecognisedSignIn("Azure Monitor record without properties")
    cat = str(rec.get("category") or "")
    merged = dict(props)
    merged.setdefault("createdDateTime", rec.get("time"))
    merged.setdefault("ipAddress", rec.get("callerIpAddress"))
    hint = None
    if cat.lower() == "signinlogs":
        hint = True
    elif cat.lower() == "noninteractiveusersigninlogs":
        hint = False
    ev = normalize_graph_signin(merged, interactive_hint=hint)
    if cat.lower() in ("signinlogs", "noninteractiveusersigninlogs"):
        ev.interactive = 1 if hint else 0
        ev.source = SOURCE_INTERACTIVE if hint else SOURCE_NONINTERACTIVE
        ev.details["interactive_basis"] = f"Azure Monitor category {cat}"
    ev.details["envelope"] = "azure_monitor"
    return ev


# ----------------------------------------------------------------------------- CSV

# canonical name -> accepted header spellings (compared lower-case, whitespace collapsed)
CSV_COLUMNS: dict[str, tuple[str, ...]] = {
    "date": ("date (utc)", "date", "created date time (utc)", "createddatetime"),
    "request_id": ("request id", "id"),
    "user_agent": ("user agent", "useragent"),
    "correlation_id": ("correlation id",),
    "user_id": ("user id",),
    "user": ("user",),
    "username": ("username", "user principal name", "userprincipalname"),
    "incoming_token_type": ("incoming token type",),
    "auth_protocol": ("authentication protocol",),
    "token_id": ("unique token identifier",),
    "application": ("application",),
    "application_id": ("application id",),
    "resource": ("resource",),
    "ip": ("ip address",),
    "location": ("location",),
    "status": ("status",),
    "error_code": ("sign-in error code", "error code"),
    "failure_reason": ("failure reason",),
    "client_app": ("client app",),
    "device_id": ("device id",),
    "browser": ("browser",),
    "os": ("operating system",),
    "compliant": ("compliant",),
    "managed": ("managed",),
    "join_type": ("join type",),
    "mfa_result": ("multifactor authentication result", "mfa result"),
    "mfa_method": ("multifactor authentication auth method",),
    "auth_requirement": ("authentication requirement",),
    "session_id": ("session id",),
    "is_interactive": ("is interactive", "isinteractive"),
}
CSV_REQUIRED = ("date", "request_id", "username", "ip", "status")


def map_csv_header(header: list[str]) -> dict[str, int]:
    norm = [" ".join(h.strip().lower().split()) for h in header]
    out: dict[str, int] = {}
    for canon, names in CSV_COLUMNS.items():
        for n in names:
            if n in norm:
                out[canon] = norm.index(n)
                break
    return out


def parse_location(text: str) -> tuple[str, str, str]:
    """'City, State, CC' (unconfirmed format, docs/VERIFY.md F7) -> (city, state, country)."""
    parts = [p.strip() for p in str(text or "").split(",")]
    parts = [p for p in parts]
    if not parts or parts == [""]:
        return "", "", ""
    country = parts[-1] if len(parts[-1]) == 2 and parts[-1].isalpha() else ""
    rest = parts[:-1] if country else parts
    city = rest[0] if rest else ""
    state = ", ".join(rest[1:]) if len(rest) > 1 else ""
    return city, state, country.upper()


def normalize_csv_signin(row: list[str], cols: dict[str, int], interactive_hint: bool | None) -> Event:
    def g(k: str) -> str:
        i = cols.get(k)
        return row[i].strip() if i is not None and i < len(row) else ""

    date = g("date")
    if not date:
        raise UnrecognisedSignIn("row has no date")
    ev = Event()
    try:
        ev.ts_utc, ev.ts_note = parse_ts(date, naive_zone="utc")   # 2a-1: downloads are UTC
    except TimeParseError as exc:
        raise UnrecognisedSignIn(f"bad date: {exc}") from exc
    ev.ts_original = date
    ev.category, ev.action, ev.operation = "signin", "signin", "Sign-in"
    ev.record_id = g("request_id")
    ev.request_id = ev.record_id
    ev.actor = g("username").lower()
    ev.actor_id = g("user_id")
    ev.actor_display = g("user")
    ev.user_agent = g("user_agent")
    ev.correlation_id = g("correlation_id")
    ev.token_id = g("token_id")
    ev.session_id = g("session_id")
    ev.app_name = g("application")
    ev.app_id = g("application_id")
    ev.resource = g("resource")
    ev.ip = g("ip")
    ev.geo_city, ev.geo_region, ev.geo_country = parse_location(g("location"))
    if ev.geo_country:
        ev.geo_source = "log"
    ev.outcome, ev.status_code = _outcome(g("error_code"), g("status"))
    ev.client_app = g("client_app")
    ev.device_id = g("device_id")
    ev.device_browser = g("browser")
    ev.device_os = g("os")
    ev.device_compliant = _yn(g("compliant"))
    ev.device_managed = _yn(g("managed"))
    ev.mfa_detail = g("mfa_result")
    ev.auth_requirement = _auth_req(g("auth_requirement"))
    inter = _bool(g("is_interactive")) if "is_interactive" in cols else None
    basis = "Is Interactive column"
    if inter is None:
        inter = interactive_hint if interactive_hint is not None else True
        basis = "file name" if interactive_hint is not None else "default (no column or file-name hint)"
    ev.interactive = 1 if inter else 0
    ev.source = SOURCE_INTERACTIVE if inter else SOURCE_NONINTERACTIVE
    det: dict[str, Any] = {"interactive_basis": basis}
    for k in ("incoming_token_type", "auth_protocol", "failure_reason", "mfa_method", "join_type"):
        v = g(k)
        if v:
            det[k] = v
    ev.details = det
    return ev


def interactive_hint_from_name(rel_path: str) -> bool | None:
    name = rel_path.replace("\\", "/").rsplit("/", 1)[-1].lower().replace("-", "").replace("_", "")
    if "interactiveusernoninteractiveuser" in name:
        return None  # a combined file (Microsoft-Extractor-Suite); decide per record
    if "noninteractive" in name:
        return False
    if "interactive" in name:
        return True
    return None
