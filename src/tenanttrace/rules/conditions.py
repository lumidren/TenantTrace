"""The condition language used by rule files.

A condition is a mapping. Combinators:

    {all: [cond, ...]}     every condition holds
    {any: [cond, ...]}     at least one holds
    {not: cond}            the condition does not hold
    true / false           constants

Field tests (`field` is an event attribute or a dotted path into `details`):

    {field: action, equals: inbox_rule.create}
    {field: action, in: [a, b]}
    {field: client_app, in_ci: [imap4, pop3]}          case-insensitive membership
    {field: details.move_to_folder, contains_any_ci: [rss, archive]}
    {field: details.forward_to, exists: true}
    {field: details.scopes, intersects_ci: [mail.read, mail.readwrite]}
    {field: outcome, equals: success}
    {field: details.operation_count, gte: 10}
    {field: user_agent, regex: "python|curl"}

Context tests ask the engine about the account's baseline and about indicators already
established by other findings. They are evaluated per event:

    {ctx: ip_in_baseline}           the event's IP was used by the account in the baseline
    {ctx: country_in_baseline}
    {ctx: device_in_baseline}       device id, or user agent + OS pair, seen in the baseline
    {ctx: ua_in_baseline}
    {ctx: session_flagged}          session id belongs to an access finding at probable or above
    {ctx: token_flagged}            token id belongs to an access finding at probable or above
    {ctx: ip_flagged}               IP belongs to an access finding at probable or above
    {ctx: ip_suspect}               IP belongs to any access finding (any level)
    {ctx: session_replayed}         the session id was used from two or more countries
    {ctx: external_target}          the forwarding / sharing target is outside the tenant domains
    {ctx: app_flagged}              the application id belongs to a consent finding
    {ctx: has_session_id}           the event carries a session or token identifier

In confidence conditions, `{ctx: X}` holds if any triggering event satisfies X, and
`{ctx_all: X}` holds only if all of them do. `{count_gte: N}` tests the number of
triggering events and `{distinct_gte: [field, N]}` the number of distinct values.
"""

from __future__ import annotations

import re
from typing import Any, Callable

from tenanttrace.schema import Event

_MISSING = object()


def get_field(ev: Event, path: str) -> Any:
    if path.startswith("details."):
        cur: Any = ev.details
        for part in path.split(".")[1:]:
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                return _MISSING
        return cur
    return getattr(ev, path, _MISSING)


def _present(v: Any) -> bool:
    return v is not _MISSING and v is not None and v != "" and v != [] and v != {}


def _lower(v: Any) -> Any:
    if isinstance(v, str):
        return v.lower()
    if isinstance(v, (list, tuple, set)):
        return [_lower(x) for x in v]
    return v


CtxFn = Callable[[str, Event], bool]


def eval_event(cond: Any, ev: Event, ctx: CtxFn) -> bool:
    if cond is True or cond is None:
        return True
    if cond is False:
        return False
    if not isinstance(cond, dict):
        raise ValueError(f"invalid condition: {cond!r}")
    if "all" in cond:
        return all(eval_event(c, ev, ctx) for c in cond["all"])
    if "any" in cond:
        return any(eval_event(c, ev, ctx) for c in cond["any"])
    if "not" in cond:
        return not eval_event(cond["not"], ev, ctx)
    if "ctx" in cond:
        return ctx(cond["ctx"], ev)
    if "field" in cond:
        return _field_test(cond, get_field(ev, cond["field"]))
    raise ValueError(f"unknown condition keys: {sorted(cond)}")


def _field_test(cond: dict[str, Any], v: Any) -> bool:
    for op, arg in cond.items():
        if op == "field":
            continue
        if op == "exists":
            if _present(v) != bool(arg):
                return False
            continue
        if not _present(v) and not (op == "equals" and v is not _MISSING):
            return False
        if op == "equals":
            if v != arg:
                return False
        elif op == "equals_ci":
            if _lower(v) != _lower(arg):
                return False
        elif op == "in":
            if v not in arg:
                return False
        elif op == "in_ci":
            if _lower(v) not in _lower(arg):
                return False
        elif op == "contains_any_ci":
            hay = " ".join(v) if isinstance(v, list) else str(v)
            hay = hay.lower()
            if not any(str(a).lower() in hay for a in arg):
                return False
        elif op == "intersects_ci":
            vals = v if isinstance(v, list) else [v]
            if not set(_lower(vals)) & set(_lower(arg)):
                return False
        elif op == "regex":
            if not re.search(arg, str(v), re.IGNORECASE):
                return False
        elif op in ("gt", "gte", "lt", "lte"):
            try:
                x = float(v)
            except (TypeError, ValueError):
                return False
            if op == "gt" and not x > arg:
                return False
            if op == "gte" and not x >= arg:
                return False
            if op == "lt" and not x < arg:
                return False
            if op == "lte" and not x <= arg:
                return False
        elif op == "truthy":
            is_true = str(v).strip().lower() not in ("", "false", "0", "none", "$false")
            if is_true != bool(arg):
                return False
        else:
            raise ValueError(f"unknown field operator {op!r}")
    return True


def eval_group(cond: Any, events: list[Event], ctx: CtxFn) -> bool:
    """Evaluate a confidence condition over the triggering events of a finding."""
    if cond is True or cond is None:
        return True
    if cond is False:
        return False
    if "all" in cond:
        return all(eval_group(c, events, ctx) for c in cond["all"])
    if "any" in cond:
        return any(eval_group(c, events, ctx) for c in cond["any"])
    if "not" in cond:
        return not eval_group(cond["not"], events, ctx)
    if "ctx" in cond:
        return any(ctx(cond["ctx"], e) for e in events)
    if "ctx_all" in cond:
        return all(ctx(cond["ctx_all"], e) for e in events)
    if "count_gte" in cond:
        return len(events) >= int(cond["count_gte"])
    if "distinct_gte" in cond:
        fld, n = cond["distinct_gte"]
        vals = {str(get_field(e, fld)) for e in events if _present(get_field(e, fld))}
        return len(vals) >= int(n)
    if "field" in cond:
        return any(_field_test(cond, get_field(e, cond["field"])) for e in events)
    raise ValueError(f"unknown group condition keys: {sorted(cond)}")
