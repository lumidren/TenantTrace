# TenantTrace evaluation results

Tool TenantTrace 0.1.0, rule set 2026.11.3, reference table 2026.11.17-1.

These results come from synthetic exports generated from documented layouts. They show that the
implementation matches its specification on that data; they are not a measure of how the tool
performs on real incidents.

## Summary

| Measure | Result |
|---|---|
| Scenarios | 13 |
| Expected findings detected | 56 / 56 |
| False positives in attack and degraded cases | 0 |
| False positives in benign cases | 0 |
| Benign findings within their allowed level (possible) | 8 |
| Additional findings citing attack records | 12 |
| Rules correctly reported as not assessable | 16 / 16 |
| Expected evidence gaps reported | 14 / 14 |
| Unexpected evidence gaps | 0 |
| Expected pivot accounts found | 12 / 12 |
| Extra pivot accounts | 0 |

## Per scenario

| Scenario | Kind | Findings detected | FP | Not assessable | Gaps | Pivot | Extra pivot | Seconds |
|---|---|---|---|---|---|---|---|---|
| attack_legacy_forwarding | attack | 8/8 | 0 | 0/0 | 0/0 | 3/3 | 0 | 0.83 |
| attack_oauth_consent | attack | 2/2 | 0 | 0/0 | 0/0 | 1/1 | 0 | 0.64 |
| attack_travel_delegate | attack | 7/7 | 0 | 0/0 | 0/0 | 0/0 | 0 | 0.61 |
| benign_admin_bulk | benign | 0/0 | 0 | 0/0 | 0/0 | 0/0 | 0 | 0.67 |
| benign_forwarding_vpn | benign | 0/0 | 0 | 0/0 | 0/0 | 0/0 | 0 | 0.63 |
| benign_travel_newphone | benign | 0/0 | 0 | 0/0 | 0/0 | 0/0 | 0 | 0.6 |
| demo_bec | attack | 9/9 | 0 | 1/1 | 1/1 | 1/1 | 0 | 0.68 |
| degraded_no_signins | degraded | 4/4 | 0 | 6/6 | 2/2 | 3/3 | 0 | 0.6 |
| degraded_ual_truncated | degraded | 5/5 | 0 | 0/0 | 2/2 | 3/3 | 0 | 0.98 |
| degraded_retention_7d | degraded | 3/3 | 0 | 2/2 | 2/2 | 0/0 | 0 | 0.59 |
| degraded_no_mailbox_audit | degraded | 7/7 | 0 | 1/1 | 2/2 | 1/1 | 0 | 0.51 |
| degraded_quiet_period | degraded | 7/7 | 0 | 0/0 | 1/1 | 0/0 | 0 | 0.8 |
| collector_hawk_legacy | degraded | 4/4 | 0 | 6/6 | 4/4 | 0/0 | 0 | 0.72 |

## Details

### attack_legacy_forwarding

Password spray, legacy IMAP sign-in without MFA, external mailbox forwarding. Window: 2026-09-26T02:10:00.000000Z (estimated).

- detected: TT-SIGNIN-006 for step `spray` (confirmed)
- detected: TT-SIGNIN-004 for step `imap_success` (probable)
- detected: TT-SIGNIN-001 for step `imap_success` (probable)
- detected: TT-SIGNIN-005 for step `owa_single_factor` (probable)
- detected: TT-SIGNIN-003 for step `owa_single_factor` (probable)
- detected: TT-MAIL-002 for step `forwarding` (confirmed)
- detected: TT-MAIL-004 for step `imap_sync` (confirmed)
- detected: TT-MAIL-005 for step `imap_sync` (confirmed)
- additional finding on attack records: TT-SIGNIN-003 (probable): Successful sign-in from a device or client never seen before for this account (user agent IMAP4 client) from 203.0.113.120 (1 sign-in(s))
- additional finding on attack records: TT-SIGNIN-007 (probable): 1 non-interactive sign-in(s) (token use) from 203.0.113.120 (Frankfurt am Main, DE) for Office 365 Exchange Online, an IP never seen for this account
- pivot found: owen.pryce@northgate.example
- pivot found: aisha.noor@northgate.example
- pivot found: ruth.calloway@northgate.example

### attack_oauth_consent

Consent phishing: a malicious OAuth app gets mail access, a second user also consents. Window: 2026-10-17T10:02:00.000000Z (estimated).

- detected: TT-APP-001 for step `consent` (probable)
- detected: TT-APP-002 for step `app_mail_access` (confirmed)
- pivot found: ines.carvalho@brightwater.example

### attack_travel_delegate

Impossible travel from a new device, device registration, folder permission and external sharing. Window: 2026-10-29T18:00:00.000000Z (default).

- detected: TT-SIGNIN-002 for step `foreign_signin` (probable)
- detected: TT-SIGNIN-001 for step `foreign_signin` (probable)
- detected: TT-SIGNIN-003 for step `foreign_signin` (probable)
- detected: TT-SIGNIN-007 for step `token_refresh` (probable)
- detected: TT-AUTH-002 for step `device_registration` (confirmed)
- detected: TT-MAIL-003 for step `folder_permission` (confirmed)
- detected: TT-FILE-002 for step `external_share` (confirmed)
- additional finding on attack records: TT-SIGNIN-002 (probable): Sign-ins from Singapore, SG and Leeds, GB: 10886 km apart within 0.19 h (about 58318 km/h)

### benign_admin_bulk

Benign: an IT administrator migrating files in bulk and granting shared mailbox access. Window: 2026-11-02T00:00:00.000000Z (analyst).

- allowed benign finding: TT-FILE-001 (possible): 121 file downloads within a burst starting at 2026-11-09T10:00:00.000000Z from 192.0.2.10 (threshold 15; the account's busiest 30 minutes before the window had 2)
- allowed benign finding: TT-MAIL-003 (possible): Add-MailboxPermission on mei.tanaka@kestrel.example: fiona.drake@kestrel.example granted FullAccess (by carl.jensen@kestrel.example, from 192.0.2.10)

### benign_forwarding_vpn

Benign: an internal forwarding rule and a user who always connects through a VPN. Window: 2026-10-12T00:00:00.000000Z (analyst).


### benign_travel_newphone

Benign: a business trip to Madrid and a new phone registered for MFA. Window: 2026-10-12T00:00:00.000000Z (analyst).

- allowed benign finding: TT-SIGNIN-001 (possible): Successful sign-in from Madrid, ES (198.51.100.150), a country never seen for this account before the compromise window (34 sign-in(s))
- allowed benign finding: TT-SIGNIN-007 (possible): 8 non-interactive sign-in(s) (token use) from 198.51.100.150 (Madrid, ES) for Microsoft Office, an IP never seen for this account
- allowed benign finding: TT-SIGNIN-007 (possible): 8 non-interactive sign-in(s) (token use) from 198.51.100.150 (Madrid, ES) for Microsoft Office, an IP never seen for this account
- allowed benign finding: TT-SIGNIN-007 (possible): 7 non-interactive sign-in(s) (token use) from 198.51.100.150 (Madrid, ES) for Microsoft Office, an IP never seen for this account
- allowed benign finding: TT-SIGNIN-007 (possible): 7 non-interactive sign-in(s) (token use) from 198.51.100.150 (Madrid, ES) for Microsoft Office, an IP never seen for this account
- allowed benign finding: TT-AUTH-001 (possible): User registered security info. (Microsoft Authenticator app) from 192.0.2.10 (1 record(s))

### demo_bec

Demo: AiTM phishing of a finance manager, MFA change, hiding rule, mailbox and file access. Window: 2026-10-25T10:14:00.000000Z (estimated).

- detected: TT-SIGNIN-001 for step `initial_access` (confirmed)
- detected: TT-SIGNIN-003 for step `initial_access` (probable)
- detected: TT-SIGNIN-002 for step `cookie_replay` (confirmed)
- detected: TT-AUTH-001 for step `mfa_registration` (confirmed)
- detected: TT-MAIL-001 for step `hiding_rule` (confirmed)
- detected: TT-MAIL-004 for step `mailbox_access` (confirmed)
- detected: TT-FILE-001 for step `bulk_download` (confirmed)
- detected: TT-FILE-002 for step `anonymous_links` (confirmed)
- detected: TT-MAIL-004 for step `return_mail_access` (confirmed)
- additional finding on attack records: TT-SIGNIN-002 (confirmed): Sign-ins from Leeds, GB and Dallas, US: 7445 km apart within 1.08 h (about 6904 km/h)
- additional finding on attack records: TT-SIGNIN-001 (confirmed): Successful sign-in from Amsterdam, NL (203.0.113.77), a country never seen for this account before the compromise window (2 sign-in(s))
- additional finding on attack records: TT-SIGNIN-003 (probable): Successful sign-in from a device or client never seen before for this account (Linux Chrome 126.0.0; user agent Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36) from 203.0.113.77 (2 sign-in(s))
- reported as not assessable: TT-SIGNIN-007 (required log source unavailable: entra_signin_noninteractive (not supplied))
- reported gap: missing in entra_signin_noninteractive
- pivot found: marcus.oyelaran@harborlane.example

### degraded_no_signins

Legacy/forwarding attack with the sign-in logs not supplied. Window: 2026-09-26T02:10:00.000000Z (estimated).

- detected: TT-SIGNIN-006 for step `spray` (confirmed)
- detected: TT-MAIL-002 for step `forwarding` (probable)
- detected: TT-MAIL-004 for step `imap_sync` (probable)
- detected: TT-MAIL-005 for step `imap_sync` (probable)
- reported as not assessable: TT-SIGNIN-001 (none of the log sources that record this are available: entra_signin_interactive (not supplied); entra_signin_noninteractive (not supplied))
- reported as not assessable: TT-SIGNIN-002 (none of the log sources that record this are available: entra_signin_interactive (not supplied); entra_signin_noninteractive (not supplied))
- reported as not assessable: TT-SIGNIN-003 (none of the log sources that record this are available: entra_signin_interactive (not supplied); entra_signin_noninteractive (not supplied))
- reported as not assessable: TT-SIGNIN-004 (none of the log sources that record this are available: entra_signin_interactive (not supplied); entra_signin_noninteractive (not supplied))
- reported as not assessable: TT-SIGNIN-005 (none of the log sources that record this are available: entra_signin_interactive (not supplied); entra_signin_noninteractive (not supplied))
- reported as not assessable: TT-SIGNIN-007 (required log source unavailable: entra_signin_noninteractive (not supplied))
- reported gap: missing in entra_signin_interactive
- reported gap: missing in entra_signin_noninteractive
- pivot found: owen.pryce@northgate.example
- pivot found: aisha.noor@northgate.example
- pivot found: ruth.calloway@northgate.example

### degraded_ual_truncated

Legacy/forwarding attack with the audit log export cut off before the attack ended. Window: 2026-09-26T02:10:00.000000Z (estimated).

- detected: TT-SIGNIN-006 for step `spray` (confirmed)
- detected: TT-SIGNIN-004 for step `imap_success` (probable)
- detected: TT-SIGNIN-001 for step `imap_success` (probable)
- detected: TT-SIGNIN-005 for step `owa_single_factor` (probable)
- detected: TT-SIGNIN-003 for step `owa_single_factor` (probable)
- additional finding on attack records: TT-SIGNIN-003 (probable): Successful sign-in from a device or client never seen before for this account (user agent IMAP4 client) from 203.0.113.120 (1 sign-in(s))
- additional finding on attack records: TT-SIGNIN-007 (probable): 1 non-interactive sign-in(s) (token use) from 203.0.113.120 (Frankfurt am Main, DE) for Office 365 Exchange Online, an IP never seen for this account
- reported gap: truncated in ual
- reported gap: ends_early in ual
- pivot found: owen.pryce@northgate.example
- pivot found: aisha.noor@northgate.example
- pivot found: ruth.calloway@northgate.example

### degraded_retention_7d

Impossible-travel attack with sign-in logs limited to the last 7 days. Window: 2026-10-29T18:00:00.000000Z (default).

- detected: TT-AUTH-002 for step `device_registration` (probable)
- detected: TT-MAIL-003 for step `folder_permission` (probable)
- detected: TT-FILE-002 for step `external_share` (probable)
- reported as not assessable: TT-SIGNIN-001 (the account's successful sign-ins before the compromise window reach back 0.0 day(s) (0 record(s)); this rule needs at least 14 days and 10 records of history to say what is unusual for the account; the early part of the compromise window is not covered: entra_signin_interactive starts 2026-11-06T08:17Z, entra_signin_noninteractive starts 2026-11-05T18:33Z; retention gap in entra_signin_interactive (2026-10-13 to 2026-11-06); retention gap in entra_signin_noninteractive (2026-10-13 to 2026-11-05))
- reported as not assessable: TT-SIGNIN-003 (the account's successful sign-ins before the compromise window reach back 0.0 day(s) (0 record(s)); this rule needs at least 14 days and 10 records of history to say what is unusual for the account; the early part of the compromise window is not covered: entra_signin_interactive starts 2026-11-06T08:17Z, entra_signin_noninteractive starts 2026-11-05T18:33Z; retention gap in entra_signin_interactive (2026-10-13 to 2026-11-06); retention gap in entra_signin_noninteractive (2026-10-13 to 2026-11-05))
- reported gap: retention in entra_signin_interactive
- reported gap: retention in entra_signin_noninteractive

### degraded_no_mailbox_audit

Demo attack with mailbox auditing absent (no mailbox item records). Window: 2026-10-25T10:14:00.000000Z (estimated).

- detected: TT-SIGNIN-001 for step `initial_access` (confirmed)
- detected: TT-SIGNIN-003 for step `initial_access` (probable)
- detected: TT-SIGNIN-002 for step `cookie_replay` (confirmed)
- detected: TT-AUTH-001 for step `mfa_registration` (confirmed)
- detected: TT-MAIL-001 for step `hiding_rule` (confirmed)
- detected: TT-FILE-001 for step `bulk_download` (confirmed)
- detected: TT-FILE-002 for step `anonymous_links` (confirmed)
- additional finding on attack records: TT-SIGNIN-002 (confirmed): Sign-ins from Leeds, GB and Dallas, US: 7445 km apart within 1.08 h (about 6904 km/h)
- additional finding on attack records: TT-SIGNIN-001 (confirmed): Successful sign-in from Amsterdam, NL (203.0.113.77), a country never seen for this account before the compromise window (2 sign-in(s))
- additional finding on attack records: TT-SIGNIN-003 (probable): Successful sign-in from a device or client never seen before for this account (Linux Chrome 126.0.0; user agent Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36) from 203.0.113.77 (2 sign-in(s))
- reported as not assessable: TT-MAIL-004 (required log source unavailable: ual_mailbox_items (the export is present but holds none of these records: auditing appears to be off))
- reported gap: missing in entra_signin_noninteractive
- reported gap: auditing_absent in ual_mailbox_items
- pivot found: marcus.oyelaran@harborlane.example

### degraded_quiet_period

Impossible-travel attack with two working days missing from the audit log export. Window: 2026-10-29T18:00:00.000000Z (default).

- detected: TT-SIGNIN-002 for step `foreign_signin` (probable)
- detected: TT-SIGNIN-001 for step `foreign_signin` (probable)
- detected: TT-SIGNIN-003 for step `foreign_signin` (probable)
- detected: TT-SIGNIN-007 for step `token_refresh` (probable)
- detected: TT-AUTH-002 for step `device_registration` (confirmed)
- detected: TT-MAIL-003 for step `folder_permission` (confirmed)
- detected: TT-FILE-002 for step `external_share` (confirmed)
- additional finding on attack records: TT-SIGNIN-002 (probable): Sign-ins from Singapore, SG and Leeds, GB: 10886 km apart within 0.19 h (about 58318 km/h)
- reported gap: quiet in ual

### collector_hawk_legacy

Legacy/forwarding attack collected with Hawk for the one compromised user. Window: 2026-09-26T02:10:00.000000Z (estimated).

- detected: TT-SIGNIN-006 for step `spray` (probable)
- detected: TT-MAIL-002 for step `forwarding` (probable)
- detected: TT-MAIL-004 for step `imap_sync` (probable)
- detected: TT-MAIL-005 for step `imap_sync` (probable)
- reported as not assessable: TT-SIGNIN-001 (none of the log sources that record this are available: entra_signin_interactive (not supplied); entra_signin_noninteractive (not supplied))
- reported as not assessable: TT-SIGNIN-002 (none of the log sources that record this are available: entra_signin_interactive (not supplied); entra_signin_noninteractive (not supplied))
- reported as not assessable: TT-SIGNIN-003 (none of the log sources that record this are available: entra_signin_interactive (not supplied); entra_signin_noninteractive (not supplied))
- reported as not assessable: TT-SIGNIN-004 (none of the log sources that record this are available: entra_signin_interactive (not supplied); entra_signin_noninteractive (not supplied))
- reported as not assessable: TT-SIGNIN-005 (none of the log sources that record this are available: entra_signin_interactive (not supplied); entra_signin_noninteractive (not supplied))
- reported as not assessable: TT-SIGNIN-007 (required log source unavailable: entra_signin_noninteractive (not supplied))
- reported gap: missing in entra_signin_interactive
- reported gap: missing in entra_signin_noninteractive
- reported gap: auditing_absent in ual_sharepoint
- reported gap: filtered in ual

