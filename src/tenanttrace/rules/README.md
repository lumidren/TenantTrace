# TenantTrace rules

Each `TT-*.yaml` file is one detection. Rules are data: the engine (`engine.py`) knows how to
evaluate rule kinds and conditions, but no detection logic lives in code.

## Fields

| Field | Meaning |
|---|---|
| `id`, `version`, `title` | identity; bump `version` and `ruleset.yaml` when a rule changes |
| `kind` | `match`, `threshold`, `deviation`, `sequence` or `travel` |
| `stage` | `access` rules (sign-in behaviour) run first; their findings at probable or above mark IPs, sessions and tokens as attacker-linked for `post` rules |
| `phase` | where the step sits in the timeline (initial_access, credential_access, persistence, defense_evasion, collection, exfiltration) |
| `attack` | MITRE ATT&CK techniques (IDs confirmed in docs/sources/attack-techniques.md) |
| `sources` | `all:` sources that must all be available; `any:` at least one must be |
| `needs_baseline_days`, `needs_baseline_events`, `baseline_kind` | history the rule needs before the compromise window; otherwise it reports "could not be assessed" |
| `needs_fields`, `field_category` | fields that must exist in the supplied records (for example coordinates for impossible travel) |
| `depends_on_access` | the rule only links activity to attacker access; it cannot be assessed when no sign-in rule could be |
| `anchor` | baseline-independent rule used to estimate the compromise window when the analyst gives none |
| `select` | which events are candidates (condition language below) |
| `group` | merge matching events into one finding by fields and time |
| `threshold` / `deviation` / `sequence` / `travel` | kind-specific parameters |
| `summary` | template for the finding's one-line statement (`{field}`, `{details.x}`, `{extra.x}`, `{count}`) |
| `why`, `benign` | why the behaviour is suspicious, and the known benign explanations |
| `confidence` | ordered list of `{level, when, reason}`; the first `when` that holds sets the level and the printed reason |

## Condition language

Combinators: `{all: [...]}`, `{any: [...]}`, `{not: ...}`, `true`.

Field tests: `{field: action, equals: x}`, `in`, `in_ci`, `equals_ci`, `contains_any_ci`,
`intersects_ci` (lists), `regex`, `exists`, `truthy`, `gt`/`gte`/`lt`/`lte`. A `field` is an event
attribute (`ip`, `client_app`, ...) or a path into details (`details.keywords`).

Context tests (`{ctx: name}`) ask about the account's baseline and about indicators already
established by other findings:

| Predicate | True when |
|---|---|
| `ip_in_baseline` | the event's IP was used by the account before the compromise window |
| `country_in_baseline` | the sign-in country appears in the account's baseline sign-ins |
| `device_in_baseline` | device ID, or OS and browser with the same user-agent family, seen in the baseline |
| `ua_in_baseline` | the user-agent family was seen in the baseline |
| `known_context` | IP and device both in the baseline |
| `session_flagged`, `token_flagged`, `session_or_token_flagged` | the session or token ID belongs to an access finding at probable or above |
| `ip_flagged` | the IP belongs to an access finding at probable or above (never a baseline IP) |
| `ip_suspect` | the IP belongs to any access finding |
| `session_replayed` | the session's own sign-ins imply impossible travel (or two countries within an hour when there are no coordinates) |
| `external_target` | a forwarding or sharing target is outside the tenant's domains |
| `app_flagged` | the application ID belongs to a consent finding |
| `ip_failed_many_users` | the IP failed to sign in to three or more accounts in the tenant |
| `in_window` | the event is inside the compromise window |
| `has_session_id` | the event carries a session or token identifier |

In `confidence` conditions, `{ctx: X}` holds if any triggering event satisfies X and
`{ctx_all: X}` only if all do; `{count_gte: N}` and `{distinct_gte: [field, N]}` test the evidence set.

The three levels and what they mean are defined in docs/CONFIDENCE.md.
