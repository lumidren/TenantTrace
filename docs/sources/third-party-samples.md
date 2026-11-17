# Public sample Microsoft 365 and Entra logs

- **Retrieved:** 2026-11-17.
- **Goal:** find small, permissively licensed public samples of real M365 UAL or Entra log data for TenantTrace parser tests.
- **Download rule applied:** a file was downloaded only if it was under 5 MB, under a clearly permissive licence (MIT, Apache-2.0, CC-BY or CC0), actual M365 or Entra log data, and readable as plain text.
- **Method:** repository metadata and licences were taken from the GitHub REST API, and files were read as text only. Archives were **not** downloaded or extracted.

## Summary

| # | Candidate | Licence | Size and format | M365/Entra log data? | Downloaded? |
|---|---|---|---|---|---|
| 1 | **splunk/attack_data**, selected O365 and Entra datasets | **Apache-2.0** (repo `LICENSE`; README "Licensed under the Apache License, Version 2.0") | 1.4 KB – 116 KB per file; JSON Lines; files are stored in Git LFS | Yes. UAL records (`o365:management:activity`) and Entra sign-in logs (`azure:monitor:aad`) from Splunk's attack_range lab tenant | **Yes, 4 files** (see below) |
| 2 | **invictus-ir/o365_dataset** | **CC-BY-4.0** (GitHub SPDX; README badge) | `auditrecords.7z`, **598,237 bytes**; the README reports 9,608 records and says it extracts to JSON/CSV | The README says yes: UAL records "from real BEC intrusions" | **No.** It is a 7z archive and cannot be read as text without extraction, which was out of scope. Real-incident data also needs a privacy review first. |
| 3 | **OTRF/Security-Datasets**, `datasets/compound/GoldenSAMLADFSMailAccess` | **MIT** (GitHub SPDX) | `AADAuditEvents.Zip` 1,788 B; `OfficeActivityEvents.Zip` 1,034 B; `Microsoft365DefenderEvents.Zip` 3,159 B; `WindowsEvents.Zip` 7,544 B | Probably. The names suggest Log Analytics/Sentinel table exports (AAD audit, OfficeActivity) from the SimuLand Golden SAML lab. **Format UNCONFIRMED.** | **No.** Zip archives. The repository was last pushed 2024-03-20. |
| 4 | **Azure/Azure-Sentinel**, `Sample Data/` | **MIT** (GitHub SPDX) | Top-level and `Custom/` listings were checked | **No** UAL or Entra sign-in sample was found at those levels. `Custom/ESI-ExchangeAdminAuditLogs-SampleData.json` (61,019 B) is *Exchange on-premises* admin audit data, not M365 UAL. `AADUSerInfo.csv` (5,420 B) is user inventory, not logs. | No |
| 5 | **marichu-kt/M365Triage** (found by GitHub search) | GitHub reports `NOASSERTION` (unclear) | Not examined | Unknown | No (licence unclear) |

## 1. splunk/attack_data: details of the downloaded files

- **Repository:** https://github.com/splunk/attack_data
  - Licence: Apache-2.0. The README states "Copyright 2025 Splunk Inc." There is no NOTICE file.
  - Not archived. Default branch `master`.
  - Pinned commit: `eb3ab7424aaa4bd7ac8e97fd0af6c1d29944d23c`.
- **Local folder:** `samples/third_party/splunk-attack-data/`. Each file is in its own subfolder, and `ATTRIBUTION.md` holds the source URLs, licence link, SHA-256 hashes and retrieval date.
- **Integrity:** every downloaded file's SHA-256 matches the `oid` in its Git LFS pointer at the pinned commit.

| File | Bytes | Records | Event time span (from records) | Content |
|---|---|---|---|---|
| `o365_email_forwarding_rule_created.log` | 8,494 | 6 | 2024-03-27 22:14 to 2024-03-28 19:02 (UTC per schema; no zone suffix) | UAL **AuditData-level** JSON, one record per line. Operations: `New-InboxRule` ×4, `UpdateInboxRules` ×1, `set-InboxRule` ×1 (**lower-case s**). `RecordType` 1 (ExchangeAdmin), `Workload` Exchange. `ClientIP` includes `:port`. `Parameters` is a `[{Name,Value}]` array. |
| `o365_suspicious_mailbox_rule.log` | 1,440 | 1 (no trailing newline) | 2025-01-14 15:12:33 | One `New-InboxRule` record. Placeholder identities (`example@acme.com`; documentation IP `198.51.100.140`). `AppAccessContext.AADSessionId` present. |
| `azure_ad_multiple_denied_mfa_requests.log` | 46,430 | 11 | 2023-10-19, about 19:00 | Entra sign-in logs in the **Azure Monitor diagnostic-settings schema**. Top-level fields: `time, resourceId, operationName ("Sign-in activity"), category ("SignInLogs"), tenantId, resultType ("500121"), resultDescription, callerIpAddress, correlationId, identity, Level, location, properties{…}`. `properties` holds Graph-style signIn fields (`userPrincipalName, appDisplayName, status, deviceDetail, mfaDetail, conditionalAccessStatus, …`). Upstream says tenant-specific details were replaced. |
| `azure_ad_distributed_spray.log` | 116,354 | 31 (file starts with 2 blank lines) | 2023-11-06 20:22 to 20:52 | Same Azure Monitor `SignInLogs` schema. Every record has `resultType` `50126` (invalid username or password). |

**Parser lessons from these samples (observed):**
- Records are **not** in time order; two files run newest to oldest.
- Operation names can vary in case.
- Files can contain blank lines.
- `ClientIP` may carry a port.
- Entra data can arrive in the Azure Monitor envelope (`category`/`properties`), which is a different shape from Graph API or admin-centre downloads.

**Other relevant attack_data folders, not downloaded** (paths exist at the pinned commit; sizes not checked, so UNCONFIRMED):
- `T1114.003/o365_mailbox_forwarding_enabled`
- `T1098.002/o365_full_access_as_app_permission_assigned`
- `T1098.002/o365_mailbox_folder_read_granted`
- `T1110.003/o365_distributed_spray`
- `T1621/o365_multiple_failed_mfa_requests`
- `T1621/azuread`
- `T1528/o365_user_consent_*`
- `T1528/azure_ad_user_consent_*`
- `T1528/device_code_authentication`

## 2. invictus-ir/o365_dataset: details

- **Repository:** https://github.com/invictus-ir/o365_dataset
  - Licence: CC-BY-4.0. Created 2021-07-15. Last push 2026-08-12.
  - Commit seen: `405ce04d339d423c98780498760a6faef13397a2`.
  - Files: `auditrecords.7z` (598,237 B), `LICENSE`, `CITATION.cff`, `README.md`.
- **README claims** (not verified, because the archive was not opened):
  - UAL records from real business email compromise incidents.
  - Covers inbox-rule manipulation and mailbox-permission abuse, plus the surrounding sign-in and admin activity.
  - Extracts to JSON or CSV.
- **Why it was not downloaded:**
  - It is a 7z archive. Inspecting it means extracting it with an archive tool, which goes beyond reading as text and was out of scope. No check was made for whether such a tool is installed.
  - It is described as real-incident data, so it should be reviewed for residual personal data before use.
  - It is a strong candidate if the user approves fetching and extracting it.

## Open questions

1. Should TenantTrace use the invictus-ir dataset (CC-BY-4.0, real BEC data)? It would need extraction with 7-Zip, a check for residual personal data, and attribution under CC-BY-4.0.
2. What format are the OTRF Golden SAML zip files: Log Analytics exports or raw API JSON? They are tiny (about 1–8 KB). Are they real archives, or something else?
3. Do any **raw `Search-UnifiedAuditLog` CSV exports** (wrapper columns `CreationDate, UserIds, Operations, AuditData`) or **Entra admin-centre downloads** exist publicly under a permissive licence? None was found in this pass. All Splunk samples are API or Azure Monitor shapes, not collector or portal exports.
4. Fixtures from elastic/integrations (o365 and azure test pipelines) and from panther-labs/panther-analysis were **not checked**. Their licences (believed to be Elastic License 2.0 and Apache-2.0 respectively) need verification before use.
5. Microsoft Learn/Graph documentation includes example JSON (for example the signIn responses in the Graph `signin-list` page). The documentation content licence was not checked, so it was not used.
6. Apache-2.0 redistribution: add the full licence text next to the Splunk samples before publishing them.
