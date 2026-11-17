"""Timestamp parsing into UTC, keeping a note of how each value was interpreted.

Real exports mix ISO 8601 (with `Z`, with an offset, or with no zone at all), .NET round-trip
values with seven fractional digits, and culture-formatted values such as `10/26/2026 3:15:02 PM`
written by PowerShell's Export-Csv. A value without a zone is only converted when the caller
states what the source documents its zone to be; otherwise the note records the assumption.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

_ISO = re.compile(
    r"^\s*(\d{4})-(\d{2})-(\d{2})[T ](\d{1,2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?\s*"
    r"(Z|z|UTC|[+-]\d{2}:?\d{2})?\s*$"
)
_SLASH = re.compile(
    r"^\s*(\d{1,2})[/.](\d{1,2})[/.](\d{4})[ T]+(\d{1,2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?\s*"
    r"([AaPp][Mm])?\s*(Z|UTC|[+-]\d{2}:?\d{2})?\s*$"
)
_EPOCH_MS = re.compile(r"^\s*/Date\((-?\d+)([+-]\d{4})?\)/\s*$")


class TimeParseError(ValueError):
    pass


def _tz(tok: str | None) -> timezone | None:
    if not tok:
        return None
    if tok in ("Z", "z", "UTC"):
        return timezone.utc
    sign = 1 if tok[0] == "+" else -1
    digits = tok[1:].replace(":", "")
    return timezone(sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:4])))


def _micro(frac: str | None) -> int:
    if not frac:
        return 0
    return int((frac + "000000")[:6])


def fmt_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_ts(value: str, naive_zone: str = "utc", day_first: bool | None = None) -> tuple[str, str]:
    """Parse `value` and return (UTC ISO string, interpretation note).

    naive_zone: what a value without a zone means, as documented for its source:
      "utc"      - documented as UTC
      "unknown"  - not documented; treated as UTC and flagged in the note
    day_first: for slash dates, True for D/M/Y, False for M/D/Y, None to infer (M/D/Y when
      both readings are valid, flagged in the note).
    """
    if value is None:
        raise TimeParseError("empty timestamp")
    s = str(value).strip()
    if not s:
        raise TimeParseError("empty timestamp")

    m = _ISO.match(s)
    if m:
        y, mo, d, hh, mi, ss, frac, z = m.groups()
        dt = datetime(int(y), int(mo), int(d), int(hh), int(mi), int(ss or 0), _micro(frac))
        tz = _tz(z)
        if tz is not None:
            note = "ISO 8601 with zone" if tz == timezone.utc else f"ISO 8601 with offset {z}"
            return fmt_utc(dt.replace(tzinfo=tz)), note
        return fmt_utc(dt.replace(tzinfo=timezone.utc)), _naive_note(naive_zone)

    m = _SLASH.match(s)
    if m:
        a, b, y, hh, mi, ss, frac, ampm, z = m.groups()
        a_i, b_i = int(a), int(b)
        note_order = ""
        if day_first is None:
            if a_i > 12 and b_i <= 12:
                day_first = True
            elif b_i > 12 and a_i <= 12:
                day_first = False
            else:
                day_first = False
                note_order = "; ambiguous day/month order, read as M/D/Y"
        day, month = (a_i, b_i) if day_first else (b_i, a_i)
        hour = int(hh)
        if ampm:
            ap = ampm.upper()
            if hour == 12:
                hour = 0
            if ap == "PM":
                hour += 12
        try:
            dt = datetime(int(y), month, day, hour, int(mi), int(ss or 0), _micro(frac))
        except ValueError as exc:
            raise TimeParseError(f"invalid date {s!r}: {exc}") from exc
        order = "D/M/Y" if day_first else "M/D/Y"
        tz = _tz(z)
        if tz is not None:
            return fmt_utc(dt.replace(tzinfo=tz)), f"{order} with zone {z}{note_order}"
        return fmt_utc(dt.replace(tzinfo=timezone.utc)), f"{order}; {_naive_note(naive_zone)}{note_order}"

    m = _EPOCH_MS.match(s)
    if m:
        ms = int(m.group(1))
        dt = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(milliseconds=ms)
        return fmt_utc(dt), "Microsoft JSON date (epoch milliseconds, UTC)"

    raise TimeParseError(f"unrecognised timestamp format: {s[:40]!r}")


def _naive_note(naive_zone: str) -> str:
    if naive_zone == "utc":
        return "no zone in value; source documents UTC"
    return "no zone in value and none documented; treated as UTC (unverified)"


def parse_utc(value: str) -> datetime:
    """Parse one of our own normalized UTC strings back into an aware datetime."""
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def parse_user_time(value: str) -> datetime:
    """Parse an analyst-supplied time (CLI argument); naive values are UTC."""
    v = value.strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", v):
        v += "T00:00:00Z"
    iso, _ = parse_ts(v, naive_zone="utc")
    return parse_utc(iso)
