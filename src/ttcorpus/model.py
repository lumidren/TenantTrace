"""Format-independent activity model for synthetic tenants.

Scenarios produce `SignIn` and `AuditOp` activities. Writers render the same activities into
each export format, so one scenario yields consistent Purview CSV, PowerShell CSV, Entra CSV,
Entra JSON and collector-layout exports.
"""

from __future__ import annotations

import random
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any


@dataclass(frozen=True)
class Loc:
    key: str
    city: str
    state: str
    country: str      # ISO 3166-1 alpha-2
    lat: float
    lon: float


# Real city names and approximate public coordinates. Used only for synthetic data.
LOCATIONS: dict[str, Loc] = {
    loc.key: loc
    for loc in [
        Loc("leeds", "Leeds", "England", "GB", 53.8008, -1.5491),
        Loc("london", "London", "England", "GB", 51.5074, -0.1278),
        Loc("manchester", "Manchester", "England", "GB", 53.4808, -2.2426),
        Loc("amsterdam", "Amsterdam", "Noord-Holland", "NL", 52.3676, 4.9041),
        Loc("frankfurt", "Frankfurt am Main", "Hessen", "DE", 50.1109, 8.6821),
        Loc("madrid", "Madrid", "Madrid", "ES", 40.4168, -3.7038),
        Loc("lisbon", "Lisbon", "Lisboa", "PT", 38.7223, -9.1393),
        Loc("newyork", "New York", "New York", "US", 40.7128, -74.0060),
        Loc("dallas", "Dallas", "Texas", "US", 32.7767, -96.7970),
        Loc("toronto", "Toronto", "Ontario", "CA", 43.6532, -79.3832),
        Loc("lagos", "Lagos", "Lagos", "NG", 6.5244, 3.3792),
        Loc("singapore", "Singapore", "Singapore", "SG", 1.3521, 103.8198),
        Loc("saopaulo", "Sao Paulo", "Sao Paulo", "BR", -23.5505, -46.6333),
        Loc("johannesburg", "Johannesburg", "Gauteng", "ZA", -26.2041, 28.0473),
    ]
}


@dataclass
class Device:
    key: str
    device_id: str          # Entra device object id ("" for unregistered devices)
    display_name: str
    os: str
    browser: str
    user_agent: str
    compliant: bool
    managed: bool
    trust_type: str         # "", "Azure AD joined", "Azure AD registered", "Hybrid Azure AD joined"


@dataclass
class User:
    upn: str
    display: str
    object_id: str
    role: str
    home: str               # location key
    office_ip: str
    home_ip: str
    mobile_ip: str
    devices: dict[str, Device] = field(default_factory=dict)


@dataclass
class App:
    app_id: str
    name: str


# First-party application IDs below are the well-known public client IDs of Microsoft apps.
# They are listed as data for synthetic logs; TenantTrace's own reference does not rely on them.
APPS: dict[str, App] = {
    "office": App("4765445b-32c6-49b0-83e6-1d93765276ca", "OfficeHome"),
    "owa": App("00000002-0000-0ff1-ce00-000000000000", "Office 365 Exchange Online"),
    "outlook": App("d3590ed6-52b3-4102-aeff-aad2292ab01c", "Microsoft Office"),
    "outlook_mobile": App("27922004-5251-4030-b22d-91ecd9a37ea4", "Outlook Mobile"),
    "teams": App("1fec8e78-bce4-4aaf-ab1b-5451cc387264", "Microsoft Teams"),
    "onedrive": App("ab9b8c07-8f02-4f72-87fa-80105867a763", "OneDrive SyncEngine"),
    "sharepoint": App("00000003-0000-0ff1-ce00-000000000000", "Office 365 SharePoint Online"),
    "exo_powershell": App("fb78d390-0c51-40cd-8e17-fdbfab77341b", "Microsoft Exchange REST API Based Powershell"),
}

RESOURCES: dict[str, App] = {
    "exchange": App("00000002-0000-0ff1-ce00-000000000000", "Office 365 Exchange Online"),
    "sharepoint": App("00000003-0000-0ff1-ce00-000000000000", "Office 365 SharePoint Online"),
    "graph": App("00000003-0000-0000-c000-000000000000", "Microsoft Graph"),
    "office": App("4765445b-32c6-49b0-83e6-1d93765276ca", "OfficeHome"),
}


@dataclass
class SignIn:
    t: datetime
    user: User
    ip: str
    loc: Loc
    device: Device
    app: App
    resource: App
    client_app: str                 # "Browser", "Mobile Apps and Desktop clients", "IMAP4", ...
    interactive: bool
    success: bool
    error_code: int = 0
    failure_reason: str = ""
    auth_requirement: str = "multiFactorAuthentication"
    mfa_detail: str = ""            # human text for the MFA result column
    session_id: str = ""
    token_id: str = ""
    correlation_id: str = ""
    request_id: str = ""
    auth_protocol: str = "none"
    incoming_token_type: str = "none"
    tags: dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditOp:
    t: datetime
    user: User
    workload: str                   # "Exchange", "SharePoint", "OneDrive", "AzureActiveDirectory"
    record_type: int
    operation: str
    ip: str
    payload: dict[str, Any] = field(default_factory=dict)
    session_id: str = ""            # Entra session id carried in AppAccessContext where documented
    token_id: str = ""
    app_id: str = ""
    user_agent: str = ""
    result_status: str = "Succeeded"
    record_id: str = ""
    tags: dict[str, Any] = field(default_factory=dict)


class Ids:
    """Deterministic UUIDs and choices from a seeded RNG."""

    def __init__(self, seed: int):
        self.rng = random.Random(seed)

    def uuid(self) -> str:
        return str(uuid.UUID(int=self.rng.getrandbits(128), version=4))

    def token(self, n: int = 22) -> str:
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        return "".join(self.rng.choice(alphabet) for _ in range(n))


def uk_offset(t: datetime) -> timedelta:
    """UK civil time offset (BST from the last Sunday of March to the last Sunday of October, 01:00 UTC)."""
    y = t.year

    def last_sunday(month: int) -> datetime:
        d = datetime(y, month + 1, 1, tzinfo=timezone.utc) - timedelta(days=1) if month < 12 else datetime(y, 12, 31, tzinfo=timezone.utc)
        while d.weekday() != 6:
            d -= timedelta(days=1)
        return d.replace(hour=1)

    start, end = last_sunday(3), last_sunday(10)
    return timedelta(hours=1) if start <= t < end else timedelta(0)


def utc(s: str) -> datetime:
    s = s.replace("Z", "+00:00")
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
