# Collector output layouts: Microsoft-Extractor-Suite, Hawk, Untitled Goose Tool

Retrieved: **2026-11-17**. Purpose: tell TenantTrace which folders, file names and record shapes to expect from common Microsoft 365 collectors.

**Method.** Each repository's PowerShell or Python source was read as text at a pinned commit, along with its README and docs. None of the code was run. Where the docs and the code disagree, the **code at the pinned commit** wins, and the docs version is noted. Folder trees below are *derived from code*: nothing was observed from an actual run.

- **CONFIRMED** = the statement is visible in the repository source or docs at the pinned commit.
- **INFERRED** = follows from code combined with standard PowerShell behaviour, but was not observed.
- **UNCONFIRMED** = not established.

---

## 1. Microsoft-Extractor-Suite (Invictus-IR)

| Item | Value | Status |
|---|---|---|
| Repository | https://github.com/invictus-ir/Microsoft-Extractor-Suite | CONFIRMED |
| Licence | **GPL-2.0** ("GNU General Public License v2.0", from GitHub API `spdx_id` and the repo page) | CONFIRMED |
| Archived | No (`archived: false`) | CONFIRMED |
| Module version | `ModuleVersion = '4.1.0'` in `Microsoft-Extractor-Suite.psd1` | CONFIRMED |
| Latest release | `V4.1.0`, published 2026-05-06 | CONFIRMED |
| Commit inspected | `369182ee5a420657feaa7ae19f5a0cd0904a4903` (2026-11-10, default branch `main`) | CONFIRMED |
| Docs | https://microsoft-365-extractor-suite.readthedocs.io/en/latest/ (source in `docs/source/functionality/{M365,Azure}/*.rst`) | CONFIRMED |

### 1.1 Output root and naming (all collectors)

Paths are built by `Init-OutputDir` in `Microsoft-Extractor-Suite.psm1`.

- **Default:** `Output\<Component>\<yyyyMMdd-HHmmss>[-<SubComponent>]\`. The path is relative to the PowerShell working directory. The timestamp is local time from `[datetime]::Now`. CONFIRMED.
- **With `-OutputDir <dir>`:** `<dir>\<Component>\<yyyyMMdd-HHmmss>[-<SubComponent>]\`. The directory you supply must already exist. CONFIRMED.
- **Default file name:** `<yyyyMMdd-HHmmss>-<FilePostfix>.csv`, stored in `$script:outputFile`. Several cmdlets ignore this name and build their own (see the table below). CONFIRMED.
- **Merged output:** `<dir>\Merged\<MergedFileName>` when `-MergeOutput` is used. CONFIRMED.
- **Log file:** the module declares `Output\LogFile.txt`. CONFIRMED (declared). Exact behaviour UNCONFIRMED.
- **Case and triage folders:**
  - `Get-AllEvidence` joins `-OutputDir` with `$ProjectName` and sets `$script:CollectionOutputDir`. Every component it runs then nests under `<OutputDir>\<ProjectName>\<Component>\<timestamp>\`.
  - `Start-MESTriage` joins `-OutputDir` with `$TriageName`.
  - CONFIRMED (code). Resulting trees INFERRED.

### 1.2 Cmdlets relevant to TenantTrace

| Cmdlet (script) | Data source | Folder (default) | Files | Format |
|---|---|---|---|---|
| `Get-UAL` (`Scripts/Get-UAL.ps1`) | `Search-UnifiedAuditLog`, `-ResultSize 5000`, **no `-SessionCommand`** in V4.1.0 | `Output\UnifiedAuditLog\<yyyyMMdd-HHmmss>\` | One file per time window: `UAL-<windowStart yyyyMMddHHmmss>-<windowEnd yyyyMMddHHmmss>.csv` / `.json` / `.jsonl`. With `-MergeOutput`: `Merged\UAL-Combined.csv` / `.json` / `.jsonl`. | `-Output` takes `CSV` (default), `JSON`, `JSONL` or `SOF-ELK`. Optional `-AuditDataOnly`. |
| `Get-UALGraph` (`Scripts/Get-UALGraph.ps1`) | Graph Audit Search API `/security/auditLog/queries`. **beta** by default; `-UseV1` switches to v1.0. `-searchName` is mandatory. | `Output\UnifiedAuditLog\<yyyyMMdd-HHmmss>\` | `<date>-<searchName>-UnifiedAuditLog.json`, or `-partN` files when split, plus `scanId.txt` | `JSON` (default), `CSV`, `JSONL`, `SOF-ELK`; `-AuditDataOnly` |
| `Get-MailboxAuditLog` (`Scripts/Get-MailboxAuditLog.ps1`) | Calls `Get-UAL` with **`RecordType = "ExchangeItem"`** | **Nested** (INFERRED from code): `Output\Mailbox Audit Log\<ts1>\UnifiedAuditLog\<ts2>\UAL-<window>.<ext>` | Same as `Get-UAL` | Same as `Get-UAL` (default CSV) |
| `Get-MailboxAuditLogLegacy` | Legacy per-mailbox search; underlying cmdlet not inspected | `Output\Mailbox Audit Log\<ts>-Legacy\` | `<date>-mailboxAuditLog-<UPN>.csv` | CSV |
| `Get-GraphEntraSignInLogs` (`Scripts/Get-AzureEntraGraphLogs.ps1`) | Graph **beta** `/auditLogs/signIns`, filtered on `signInEventTypes`. Scopes: AuditLog.Read.All, Directory.Read.All. | `Output\EntraID\<yyyyMMdd-HHmmss>-SignInLogs\<event type folder>\` | `<yyyyMMddHHmmss>-<type>-SignInLogs.json`, one per API page, appended. With merge: `Merged\SignInLogs-<type>-Combined.json`. | `JSON` (default) or `SOF-ELK` |
| `Get-GraphEntraAuditLogs` (same script) | Graph **v1.0** `/auditLogs/directoryAudits` | `Output\EntraID\<yyyyMMdd-HHmmss>-AuditLogs\` | `<yyyyMMddHHmmss>-AuditLogs.json`. With merge: `Merged\AuditLogs-Combined.json`. | `JSON` (default) or `SOF-ELK` |
| `Get-MailboxRules` (`Scripts/Get-Rules.ps1`) | Exchange Online inbox rules for each mailbox | `Output\Rules\<yyyyMMdd-HHmmss>\` | `<date>-MailboxRules.csv` | CSV |
| `Get-MailboxRulesGraph` (same script) | Graph | `Output\Rules\<ts>\` | `<date>-MailboxRulesGraph.csv` (columns not inspected) | CSV |
| `Get-TransportRules` (same script) | Exchange Online | `Output\Rules\<ts>\` | `<date>-TransportRules.csv` | CSV |
| `Get-OAuthPermissionsGraph` (`Scripts/Get-OAuthPermissions.ps1`) | Graph: OAuth2 permission grants, app role assignments, service principals, applications | `Output\EntraID\<ts>-OAuthPermissions\`, plus `...-ServicePrincipals\` and `...-AppRegistrations\` | `<date>-OAuthPermissions.csv`, `<date>-ServicePrincipals.csv`, `<date>-AppRegistrations.csv` | CSV |
| `Get-MFA` (`Scripts/Get-MFAStatus.ps1`) | Graph v1.0 `/users/{id}/authentication/methods` and `/reports/authenticationMethods/userRegistrationDetails` | `Output\MFA\<ts>\`. INFERRED: the two files may land in different `<ts>` folders, because `Init-OutputDir` is called twice. | `<date>-AuthenticationMethods.csv`, `<date>-UserRegistrationDetails.csv` | CSV |
| Others, not inspected in detail | `Get-AdminAuditLog` → `Output\AdminAuditLog\<ts>\`; `Get-MailItemsAccessed`, `Get-Sessions`, `Get-MessageIDs` → `Output\MailItemsAccessed\<ts>\` (also `Sessions-<IP>.csv`, `<date>-MessageIDs.csv`, `.eml` downloads); `Get-MessageTraceLog`; `Get-Users`; `Get-AdminUsers`; `Get-RiskyUsers`; `Get-RiskyDetections`; `Get-ConditionalAccessPolicies`; `Get-Devices`; `Get-SecurityAlerts`; `Get-PIMAssignments` | — | — | CONFIRMED as names only |

The source code paths are CONFIRMED for every row above. The exact nested path for `Get-MailboxAuditLog` is INFERRED.

### 1.3 `Get-UAL` record shapes (CONFIRMED from code unless marked)

- **CSV, default.**
  - The script runs `Export-CSV` on the **raw `Search-UnifiedAuditLog` result objects** without choosing columns. The columns are therefore whatever properties the cmdlet returns, and `AuditData` stays a **JSON string** column.
  - The docs name wrapper properties *CreationDate, UserIds, Operations, ResultIndex*.
  - The full set is believed to be `RunspaceId, RecordType, CreationDate, UserIds, Operations, AuditData, ResultIndex, ResultCount, Identity, IsValid, ObjectState`, but this is **UNCONFIRMED** (memory, not a source).
- **CSV with `-AuditDataOnly`.**
  - Each `AuditData` string is parsed and exported, so columns are the top-level AuditData properties.
  - INFERRED: `Export-Csv` takes its header from the first object, so properties that first appear in later records can be dropped.
- **JSON.**
  - Each window file holds `ConvertTo-Json -Depth 100` of the wrapper objects, with `AuditData` **replaced by the parsed object**. A newline is appended afterwards.
  - INFERRED: a window containing one record may serialise as a single object instead of an array, which is standard Windows PowerShell `ConvertTo-Json` behaviour. Parsers should accept both.
- **JSONL.**
  - One compressed wrapper object per line. `AuditData` **remains an escaped JSON string**, because parsing only happens in the JSON and SOF-ELK branches.
  - With `-AuditDataOnly`, each line is the raw AuditData string.
- **SOF-ELK.** One compressed **AuditData object per line**, without the wrapper, written to `UAL-<window>.json` despite the `.json` extension.
- **Windowing.**
  - An initial probe sets the interval. A window that returns 5,000 events is shrunk and fetched again.
  - The shrink threshold is `min(5000-100, TargetEventsPerWindow*1.5)`, which is 4,500 with the default `TargetEventsPerWindow` of 3,000.
  - The docs say the default start date is **today minus 180 days** and the default end is now.
  - CONFIRMED.
- **Time basis of window file names.** `.ToString("yyyyMMddHHmmss")` is applied to the window start and end without `ToUniversalTime()`. Whether these names are UTC or local time is **UNCONFIRMED**.
- **V4.1.0 release notes (collector statement):** session pagination was replaced with non-session calls capped at 5,000, `Get-UALStatistics` was removed, and the notes report that `ResultCount` no longer gives the total. CONFIRMED that the notes say this; the Microsoft behaviour behind it is UNCONFIRMED.

### 1.4 Other record shapes (CONFIRMED from code)

- **`Get-UALGraph` CSV columns:** `id, createdDateTime, auditLogRecordType, operation, organizationId, userType, userId, service, objectId, userPrincipalName, clientIp, administrativeUnits` (joined with `'; '`), and `auditData` (JSON string). JSON output is an array of these records. `-AuditDataOnly` writes only `auditData`.
- **Entra sign-in JSON:**
  - Each file is `ConvertTo-Json -Depth 100` of one Graph **beta** `signIn` page (`value` array), appended with `-Append`.
  - INFERRED: if two pages finish in the same second they go into the same file name, and the file then holds two concatenated arrays. A tolerant reader should handle that.
  - SOF-ELK mode writes one compressed object per line.
- **Sign-in event-type folders.** With `-EventTypes All` (the default) and no `-UserIds`, the cmdlet processes three folders, named by `displayName`:

  | Folder | File tag |
  |---|---|
  | `interactiveUser & nonInteractiveUser` | `interactiveUser-nonInteractiveUser` |
  | `servicePrincipal` | `servicePrincipal` |
  | `managedIdentity` | `managedIdentity` |

  - With `-UserIds`, only the combined interactive and non-interactive set is collected.
  - Folder names contain spaces and `&`.
- **Entra audit JSON:** an array of Graph v1.0 `directoryAudit` objects in each file.
- **`Get-MailboxRules` CSV columns:** `UserName, RuleName, Enabled, Priority, RuleIdentity, StopProcessingRules, CopyToFolder, MoveToFolder, RedirectTo, ForwardTo, ForwardAsAttachmentTo, ApplyCategory, MarkImportance, MarkAsRead, DeleteMessage, SoftDeleteMessage, From, SubjectContainsWords, SubjectOrBodyContainsWords, BodyContainsWords, HasAttachment, Description, InError, ErrorType`. Multi-valued fields are joined with `", "`.
- **`Get-OAuthPermissionsGraph` CSV.** Rows are built from two different hash tables:
  - **Delegated grants:** `PermissionType, AppId, ClientObjectId, AppDisplayName, ResourceObjectId, ResourceDisplayName, Permission, ConsentType, PrincipalObjectId, PrincipalDisplayName, Homepage, PublisherName, ReplyUrls, ExpiryTime, CreatedDateTime, AppOwnerOrganizationId, ApplicationStatus, ApplicationVisibility, AssignmentRequired, IsAppProxy, PublisherDisplayName, VerifiedPublisherId, AddedDateTime, SignInAudience, ApplicationType`.
  - **Application permissions:** the same leading keys, plus `IsEnabled, Description, CreationTimestamp`, with `ConsentType = "AllPrincipals"`. The remaining keys were not fully read.
  - INFERRED: `Export-Csv` uses the first row's keys for the header, so the column set depends on whether the first row is delegated or application.
  - **ServicePrincipals CSV:** `AppId, AppDisplayName, AppDescription, AccountEnabled, AppOwnerOrganizationId`.
  - **AppRegistrations CSV:** `Id, DisplayName, AppId, CreatedDateTime`.
- **`Get-MFA` AuthenticationMethods CSV:** `user, MFAstatus, email, fido2, app, password, phone, softwareoath, hellobusiness, temporaryAccessPass, certificateBasedAuthConfiguration, qrcodepin`. The UserRegistrationDetails CSV columns come from the Graph report and vary.

### 1.5 Docs vs code mismatches (treat the code as authoritative)

| Cmdlet | Docs say | Code at the pinned commit does |
|---|---|---|
| `Get-UAL` | `Output\UnifiedAuditLog`, file `UAL-[$CurrentStart].[csv/json]` | `Output\UnifiedAuditLog\<ts>\UAL-<start>-<end>.<ext>` |
| `Get-MailboxAuditLog` | `Output\MailboxAuditLog`, files `MailboxAuditLog-[timestamp]` | `Output\Mailbox Audit Log\<ts>\...` (nested through Get-UAL) |
| `Get-GraphEntraSignInLogs` | `Output\EntraID\{date_SignInLogs}\SignInLogs.json` / `SignInLogsGraph.json` | Per-event-type subfolders, with per-page files |
| `Get-GraphEntraAuditLogs` | `Auditlogs.json` / `AuditlogsGraph.json` | `<ts>-AuditLogs.json` |
| `Get-OAuthPermissionsGraph` | `Output\OAuthPermissions\OAuthPermissions.csv` | `Output\EntraID\<ts>-OAuthPermissions\<ts>-OAuthPermissions.csv` |
| `Get-MailboxRules` | `Output\Rules`, `[date]-MailboxRules.csv` | Matches, with a `<ts>` subfolder |

**Implication for TenantTrace:** detect exports by **content**, not by fixed file names. Content cues include:
- Wrapper columns such as `CreationDate`/`UserIds`/`Operations`/`AuditData`.
- AuditData keys such as `CreationTime`/`RecordType`/`Workload`.
- Graph keys such as `createdDateTime`/`signInEventTypes`/`activityDisplayName`.

Treat folder names as hints only.

INFERRED parsing cautions:
- Windows PowerShell `Export-Csv -Encoding UTF8` writes a BOM.
- Folder names contain spaces and `&`.
- Per-page JSON files may need to be concatenated.

---

## 2. Hawk (T0pCyber)

| Item | Value | Status |
|---|---|---|
| Repository | https://github.com/T0pCyber/hawk | CONFIRMED |
| Licence | **MIT** (GitHub API `spdx_id: MIT`) | CONFIRMED |
| Archived | No; last push 2026-06-10; default branch `master` | CONFIRMED |
| Module version | `ModuleVersion = '4.0'` in `Hawk/Hawk.psd1` | CONFIRMED |
| Commit inspected | `a44536f2b4225dd8ea2e463db88d5db40cfac8c7` | CONFIRMED |
| GitHub "latest release" | The API returned none. Whether releases exist only on PowerShell Gallery was not checked. | UNCONFIRMED |

### 2.1 Folder layout

From `Initialize-HawkGlobalObject.ps1` and `Out-MultipleFileType.ps1`; all CONFIRMED from code.

```
<chosen root>\Hawk_<TenantName>_<yyyyMMdd_HHmmss>\        (timestamp in UTC; TenantName from org display name,
│                                                          characters \/:*?"<>| removed, whitespace -> "_")
├── Tenant\<Prefix>.csv | .json | .txt                    (tenant-wide output)
│   └── XML\<Prefix>.xml                                  (only when -xml is used)
├── <user UPN>\<Prefix>_<shortuser>.csv | .json | .txt    (shortuser = UPN text before '@')
│   └── XML\<Prefix>_<shortuser>.xml
└── _Investigate.txt                                       (lines for -Notice outputs; written next to the log file)
```

- Prefixes beginning `_Investigate_` mark findings Hawk considers suspicious.
- Prefixes beginning `Simple_` are flattened versions of UAL results.
- JSON is `ConvertTo-Json -Depth 100`. CSV is `Export-Csv -NoTypeInformation -Encoding UTF8`. Both are appended when `-Append` is set.
- The README's sample tree (`AdminAuditLogConfig.csv`, `OrgConfig.csv`, `InboxRules.csv`) is **illustrative**. The code writes `AdminAuditLogConfig.txt`, `OrgConfig.txt` and `All_InboxRules_<shortuser>.csv`, and adds the `_<shortuser>` suffix to every per-user file.

### 2.2 Key files

All CONFIRMED from code. "User" means `<UPN>\…_<shortuser>.<ext>`.

| Function | File prefix(es) | Scope | Content / columns |
|---|---|---|---|
| `Get-HawkUserUALSignInLog` | `Converted_Authentication_Logs` (csv, json); `Failed_Conversion_Authentication_Logs` | User | UAL records of RecordType `AzureActiveDirectoryAccountLogon`, `AzureActiveDirectory` and `AzureActiveDirectoryStsLogon` for the user, with AuditData flattened by `Import-AzureAuthenticationLog`. **Leading columns:** `CreationTime, UserId, Workload, ClientIP, CountryName, KnownMicrosoftIP` (the last two are Hawk enrichment), then every other property found. `ExtendedProperties` name/value pairs become columns, and `Actor`/`Target` become `id:type` lists. Rows are sorted by creation time. **The column set changes from run to run.** |
| `Get-HawkUserEntraIDSignInLog` | `Entra_Sign_In_Log_<UPN>`; `_Investigate_Entra_Sign_In_Log_<UPN>` | User | Entra sign-in records. Columns not inspected. |
| `Get-HawkUserInboxRule` | `All_InboxRules` (append); `_Investigate_InboxRules` (append) | User | Full inbox-rule objects; columns are the cmdlet's own properties, not listed here. A rule goes into `_Investigate_` if `DeleteMessage` is true or `ForwardTo`, `ForwardAsAttachmentTo` or `RedirectTo` is set. |
| `Get-HawkUserEmailForwarding` | `ForwardingReport` (user); `User_ForwardingReport` (tenant level, append); `_Investigate_Users_WithForwarding` | User and Tenant | Columns `DisplayName, UserPrincipalName, PrimarySMTPAddress, ForwardingSMTPAddress, ForwardingAddress, DeliverToMailboxAndForward, WhenChangedUTC`. The `_Investigate_` call passes no `-csv/-json` switch, and `Out-MultipleFileType` raises an error when no type is given. **That file may never be written** (code reading, not tested). |
| `Get-HawkUserMailItemsAccessed` | `MailItemsAccessed_<UPN>`; `Simple_MailItemsAccessed_<UPN>` | User | MailItemsAccessed UAL records, raw and flattened |
| `Get-HawkUserMailboxAuditing` | `ExchangeItem_Logs`, `ExchangeItem_Simple`, `ExchangeItemGroup_Logs`, `ExchangeItemGroup_Simple` | User | Mailbox-audit UAL records by record type |
| `Get-HawkUserExchangeSearchQuery` / `Get-HawkUserSharePointSearchQuery` | `ExchangeSearchQueries_<UPN>` / `SharePointSearches_<UPN>`, each with a `Simple_` version | User | Search-query audit records |
| `Get-HawkUserMailSendActivity` | `SendActivity_<UPN>`, `Simple_SendActivity_<UPN>` | User | Send audit records |
| `Get-HawkUserAdminAudit` | `User_Changes`, `Simple_User_Changes` | User | Admin changes made to the user |
| `Get-HawkUserConfiguration` | `Mailbox_Info`, `Mailbox_Statistics`, `Mailbox_Folder_Statistics`, `CAS_Mailbox_Info`, `Mailbox_Archive_Statistics` | User | `.txt` (Format-List) |
| `Get-HawkUserMobileDevice` | `_Investigate_MobileDevice` | User | Mobile devices |
| `Get-HawkTenantConfiguration` | `AdminAuditLogConfig` (txt), `OrgConfig` (txt), `RemoteDomain`, `TransportRules`, `TransportConfig` | Tenant | `AdminAuditLogConfig.txt` includes `UnifiedAuditLogIngestionEnabled`. |
| `Get-HawkTenantConsentGrant` | `Consent_Grants`, `_Investigate_Consent_Grants` | Tenant | OAuth consent grants |
| `Get-HawkTenantAdminInboxRuleCreation` / `...Modification` | `Admin_Inbox_Rules_Creation`, `Simple_…`, `_Investigate_…`; `Admin_Inbox_Rules_Modification`, `Simple_…`, `_Investigate_…` | Tenant | Admin-made inbox-rule changes |
| `Get-HawkTenantAdminEmailForwardingChange` | `Forwarding_Changes`, `Forwarding_Recipients`, `Simple_Forwarding_Changes` (all with `-Notice`) | Tenant | Forwarding configuration changes |
| `Get-HawkTenantAdminMailboxPermissionChange` | `Mailbox_Permission_Change`, `Simple_…`, `_Investigate_…` | Tenant | Mailbox permission grants |
| `Get-HawkTenantEntraIDAuditLog` / `Get-HawkTenantEntraIDUser` / `Get-HawkTenantEXOAdmin` | `EntraIDAuditLogs`, `EntraIDUsers`, `ExchangeOnlineAdministrators` | Tenant | csv and json |
| `Get-HawkTenantAppAndSPNCredentialDetail` | `ApplicationCertsAndSecrets`, `SPNCertsAndSecrets` | Tenant | csv, append |
| `Get-HawkTenantRiskyUsers` / `Get-HawkTenantRiskDetections` | `RiskyUsers`, `_Investigate_Risky_Users`, `_Investigate_Compromised_Users` (json); `Risk_Detections` (csv processed, json raw), `_Investigate_Confirmed_Compromised_Risk_Detection`, `_Investigate_Risk_Detection` | Tenant | Identity Protection data |

### 2.3 `Simple_` file columns

Built by `Get-SimpleUnifiedAuditLog`; CONFIRMED from code.

- **Content:** all `Search-UnifiedAuditLog` base properties except `AuditData`, plus flattened AuditData keys.
- **Column order:**
  1. Fixed leading columns, where present: `CreationTime, Workload, RecordType, Operation, ResultStatus, ClientIP, UserId, Id, OrganizationId, UserType, UserKey, ObjectId, Scope, AppAccessContext`.
  2. Then `ParameterString` and the `Param_*` columns, sorted.
  3. Then everything else.

---

## 3. CISA Untitled Goose Tool (quick check)

| Item | Value | Status |
|---|---|---|
| Repository | https://github.com/cisagov/untitledgoosetool | CONFIRMED |
| Archived | **No** (`archived: false` on 2026-11-17); last push 2026-10-13; default branch `develop` | CONFIRMED |
| Licence | **CC0-1.0**. The README says public domain in the US and a CC0 1.0 waiver elsewhere. | CONFIRMED |
| Latest release | `v2.1.0`, published 2025-02-19 | CONFIRMED |
| Commit inspected | `8e85710cbc986bfc4ff6eace143921c48becbdb4` | CONFIRMED |

Output layout, from `goosey/*.py` and the README; CONFIRMED from code:

```
output\                                   (default -o/--output_dir 'output')
├── m365\
│   ├── ual_<start>_<end>.json             (':' replaced by '_'; ONE AuditData JSON object PER LINE, i.e. JSON Lines)
│   └── EXO_*_PowerShell.json              (e.g. EXO_RoleGroups_, EXO_Mailboxes_, EXO_MailboxPermissions_,
│                                            EXO_TopLevelFolderPermissions_, EXO_MailboxCAS_Settings_)
├── entraid\
│   ├── signin_<source>\<source>_signin_log_<YYYY-MM-DD>.json   (Graph beta /auditLogs/signIns, appended per day)
│   └── entraid_audit_logs\entraidauditlog_<YYYY-MM-DD>.json
├── azure\ ...
├── mde\ ...
└── csvs\                                  (default destination of the CSV conversion step)
reports dir: _no_results.json, _user_inbox_503.json
```

- The sign-in `source` values in the code are `adfs`, `rt`, `sp` and `msi`. They are passed as an extra `source` query parameter, which Microsoft does not document. **How they map to Entra sign-in types is UNCONFIRMED.**
- The README says the UAL is dumped "for last year using Search-UnifiedAuditLog api". CONFIRMED (README text).
- The README notes licence requirements for some collections: risk detections need P1 plus Workload ID Premium; risky users need P2 plus Workload ID Premium. CONFIRMED (README).

---

## Open questions

1. What are the exact columns of `Get-UAL`'s default CSV (the full `Search-UnifiedAuditLog` property set in current EXO V3 module versions)? Check against a real export.
2. Are the `Get-UAL` window file names in UTC or local time? Does a single-record window produce a JSON object rather than an array in practice?
3. Does `Merge-OutputFiles` produce valid JSON when the per-window or per-page files already contain arrays? Only part of the function was read.
4. `Get-MailboxAuditLog` passes only `RecordType ExchangeItem` to `Get-UAL`. This appears to exclude `ExchangeItemGroup` (3) and `ExchangeItemAggregated` (50, MailItemsAccessed). Is that intended? TenantTrace should not treat their absence in such an export as a log gap.
5. Is the nested `Mailbox Audit Log\<ts>\UnifiedAuditLog\<ts>` path what users actually see? Derived from code; no run was observed.
6. What columns does `Get-MailboxRulesGraph` write, and what are the remaining application-permission keys in `Get-OAuthPermissionsGraph`?
7. Is Hawk distributed through PowerShell Gallery releases newer than the GitHub source (4.0)? What is the column set of `Entra_Sign_In_Log_*`?
8. How do Untitled Goose Tool's `adfs/rt/sp/msi` sign-in sources map to interactive, non-interactive, service-principal and managed-identity sign-ins? Is an interactive-only source missing?
9. Collector docs on Read the Docs could not be navigated through WebFetch. The docs were read from the `.rst` source in the repository instead.
