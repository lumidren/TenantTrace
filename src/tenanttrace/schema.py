"""The normalized event schema.

Every parser emits `Event` objects. The schema is platform-neutral: `platform` names the
cloud suite ("m365" today) and `source` names the logical log source from the gap reference
table, so a later Google Workspace parser can emit the same shape with its own sources.

Field groups:
  who      actor, actor_id, actor_display
  what     category, action (normalized vocabulary), operation (verbatim from the log), outcome, target
  when     ts_utc (normalized), ts_original (verbatim), ts_note (how it was converted)
  where    ip, geo_* (only from the log itself or an analyst-supplied offline IP database)
  how      user_agent, client_app, app_id, app_name, resource, device_*
  session  session_id, token_id, correlation_id, request_id, record_id
  origin   file_id, line_start, line_end, byte_offset, raw_sha256, parser
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, fields
from typing import Any

SCHEMA_VERSION = "1.0"

# Normalized categories. Rules match on these, never on raw operation names alone.
CATEGORIES = (
    "signin",          # authentication events
    "mail_rule",       # inbox rules
    "mailbox_config",  # forwarding, delegation, mailbox permissions
    "mail_access",     # reading / syncing mail items
    "mail_send",       # sending mail
    "mail_delete",     # deleting mail items
    "file_access",     # SharePoint / OneDrive file operations
    "sharing",         # sharing links, invitations
    "app_consent",     # OAuth consent and permission grants
    "auth_method",     # MFA / security info registration and changes
    "device",          # device registration
    "directory",       # other directory changes
    "other",
)

OUTCOMES = ("success", "failure", "interrupted", "unknown")


@dataclass
class Event:
    # identity of the record
    event_id: str = ""
    platform: str = "m365"
    source: str = ""            # logical source id, e.g. "entra_signin_interactive"
    parser: str = ""            # parser id that produced the event
    # when
    ts_utc: str = ""            # ISO 8601, UTC, microsecond precision, trailing Z
    ts_original: str = ""       # verbatim timestamp text from the record
    ts_note: str = ""           # how ts_original was interpreted
    # who
    actor: str = ""             # lower-cased UPN or principal identifier
    actor_id: str = ""
    actor_display: str = ""
    # what
    category: str = "other"
    action: str = ""            # normalized action, e.g. "inbox_rule.create"
    operation: str = ""         # verbatim operation / activity name
    outcome: str = "unknown"
    status_code: str = ""
    target: str = ""
    # where
    ip: str = ""
    geo_country: str = ""
    geo_region: str = ""
    geo_city: str = ""
    geo_lat: float | None = None
    geo_lon: float | None = None
    geo_source: str = ""        # "log" or "ipdb:<file>"
    # how
    user_agent: str = ""
    client_app: str = ""
    app_id: str = ""
    app_name: str = ""
    resource: str = ""
    device_id: str = ""
    device_name: str = ""
    device_os: str = ""
    device_browser: str = ""
    device_compliant: str = ""
    device_managed: str = ""
    interactive: int | None = None
    auth_requirement: str = ""
    mfa_detail: str = ""
    # session
    session_id: str = ""
    token_id: str = ""
    correlation_id: str = ""
    request_id: str = ""
    record_id: str = ""         # native unique id of the record in its source log
    # anything source-specific that rules may need
    details: dict[str, Any] = field(default_factory=dict)
    # origin pointer
    file_id: int = 0
    line_start: int = 0
    line_end: int = 0
    byte_offset: int | None = None
    raw_sha256: str = ""
    # cross-log linking (filled after ingest)
    link_group: str = ""
    link_role: str = ""         # "primary", "duplicate", "corroborating" or ""
    link_basis: str = ""

    def to_row(self) -> dict[str, Any]:
        row = asdict(self)
        row["details"] = json.dumps(self.details, sort_keys=True, ensure_ascii=False)
        return row

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> "Event":
        data = dict(row)
        det = data.get("details")
        data["details"] = json.loads(det) if det else {}
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})


EVENT_COLUMNS: tuple[str, ...] = tuple(f.name for f in fields(Event))
