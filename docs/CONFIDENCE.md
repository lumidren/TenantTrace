# Confidence levels

TenantTrace labels every finding with one of three fixed levels. There is no numeric score
anywhere in the tool. A level is never chosen by hand: each rule file states, in data, the
conditions for each level, the engine applies the first level whose conditions hold, and the
report prints the matching reason beside the label.

The levels answer one question: **how strongly does the supplied evidence support the claim
that this activity was performed by an adversary?** They do not grade how bad the activity
would be if it were malicious.

## The three levels

### Confirmed

The logs record the suspicious action itself, **and** the action is tied to adversary access
by an identifier that the logs themselves carry, with no inference needed for the link.

All of the following hold:

1. The triggering event is an observed record of the action (not an absence, not a count).
2. The action is linked to an access path already established as adversarial by one of:
   - the same Entra session ID or token identifier as a sign-in that is itself a finding at
     probable or confirmed level, or
   - a sign-in whose own triggering events include a session that was used from two
     incompatible locations (session replay), or
   - an indicator that the analyst has marked as known-bad (not used by the built-in rules).
3. None of the rule's listed benign explanations is supported by the context the engine can
   check (for example the action did not come from a device and IP address both present in
   the account's baseline).

### Probable

The logs record the suspicious action, and **two or more independent indicators** point to
adversary activity, but the link to adversary access rests on correlation (same IP address,
close in time) rather than a recorded session or token identifier.

Typical cases:

- the action came from an IP address that was never seen for the account during the baseline
  and that an access-type finding has already flagged, without a shared session ID;
- the action itself has two suspicious properties at once (for example an inbox rule that both
  matches payment keywords and moves mail to an obscure folder) and came from outside the
  account's baseline.

### Possible

A single indicator, or a pattern for which benign explanations remain about as plausible as a
malicious one. A possible finding is a lead for the analyst, not a conclusion.

Typical cases:

- a sign-in from a country absent from the baseline, with nothing else unusual about it;
- a security-info registration performed from a known device and IP address;
- bulk file activity by an account whose baseline already includes bulk work.

## How levels interact with evidence gaps

- A level is never raised because evidence is missing. Absence of a benign explanation that
  the logs could not show is not treated as support for a malicious one.
- When a rule depends on a source that is missing, or on a baseline the logs cannot
  establish, the rule reports **could not be assessed** with the reason. It never reports
  "nothing found" in that situation.
- When a session ID is not present in a source, any link from a sign-in to later activity is
  labelled as an inference in the timeline, and the finding cannot be confirmed on the
  strength of that link.

## Where the criteria live

Each rule YAML file under `src/tenanttrace/rules/` has a `confidence` list. Entries are tried in
order (confirmed, probable, possible); each has a `when` condition over the triggering events
and engine context, and a `reason` template printed in the report. The context predicates
available to rules are documented in `src/tenanttrace/rules/README.md`.
