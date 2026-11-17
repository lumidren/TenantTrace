# Microsoft 365 log export formats: verified field reference

Ground truth for the TenantTrace parsers. Every field name, column header, enum value and limit below is
tagged with where it came from and how sure we are. Where Microsoft does not document something, this file
says so instead of guessing.

- **Retrieval date for every source in this file:** 2026-11-17
- **Scope:** Unified audit log (UAL) exports, Microsoft Entra sign-in and audit log exports, and the
  identifiers that link the two.

## How this was verified

- Where Microsoft publishes the doc source on GitHub, the raw Markdown was read directly and searched for
  exact strings (repos: `MicrosoftDocs/office-365-management-api`, `MicrosoftDocs/office-docs-powershell`,
  `MicrosoftDocs/entra-docs`, `microsoftgraph/microsoft-graph-docs-contrib`).
- Purview pages (no public source repo found) were read from the rendered learn.microsoft.com page text.
- Field names were copied from the source text, not from a summary. Descriptions here are paraphrases.
- Nothing was downloaded to disk, no code from these pages was run.

## Status legend

| Tag | Meaning |
|---|---|
| **CONFIRMED** | The exact name or value appears in Microsoft documentation (URL given). |
| **PARTIAL** | Microsoft documents the concept or a nearby form (prose, UI label, another log surface), but not the exact export key or header. |
| **UNCONFIRMED** | Not found in Microsoft documentation. Given as best knowledge from real exports, with the reason. Must be checked against a real sample before a parser relies on it. |
| **CONFLICT** | Microsoft sources disagree with each other. Both forms are listed. |

## Source index

| ID | Page | URL | Doc date shown by Microsoft |
|---|---|---|---|
| S1 | Office 365 Management Activity API schema | https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema (raw: https://github.com/MicrosoftDocs/office-365-management-api/blob/main/office-365-management-api/office-365-management-activity-api-schema.md) | ms.date 2026-10-01 |
| S2 | Office 365 Management Activity API reference (sample records) | https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-reference | ms.date 2024-12-03 |
| S3 | Search-UnifiedAuditLog cmdlet | https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/search-unifiedauditlog (raw: https://github.com/MicrosoftDocs/office-docs-powershell/blob/main/exchange/exchange-ps/ExchangePowerShell/Search-UnifiedAuditLog.md) | none shown |
| S4 | Export, configure, and view audit log records | https://learn.microsoft.com/en-us/purview/audit-log-export-records | 2026-06-19 |
| S5 | Search the audit log | https://learn.microsoft.com/en-us/purview/audit-search (the old `audit-new-search` URL redirects here) | 2026-06-19 |
| S6 | Detailed activity properties in the audit log | https://learn.microsoft.com/en-us/purview/audit-log-detailed-properties | 2026-02-18 |
| S7 | Audit log activities | https://learn.microsoft.com/en-us/purview/audit-log-activities | 2026-11-03 |
| S8 | Use a PowerShell script to search the audit log | https://learn.microsoft.com/en-us/purview/audit-log-search-script | 2026-06-19 |
| S9 | Learn about properties in Exchange audit records | https://learn.microsoft.com/en-us/purview/audit-log-exchange-properties | ms.date 2026-06-19, updated 2026-06-24 |
| S10 | Use MailItemsAccessed to investigate compromised accounts | https://learn.microsoft.com/en-us/purview/audit-log-investigate-accounts | 2026-06-24 |
| S11 | Learn training unit: Investigate compromised email accounts (Purview Audit Premium) | https://learn.microsoft.com/en-us/training/modules/investigate-threats-using-audit-in-microsoft-365-defender-microsoft-purview-premium/5-investigate-compromised-email-accounts | ms.date 2023-03-22 |
| S12 | Use sharing auditing in the audit log | https://learn.microsoft.com/en-us/purview/audit-log-sharing | ms.date 2026-06-19, updated 2026-06-24 |
| S13 | Exchange cmdlet references (New-InboxRule, Set-InboxRule, Remove-InboxRule, Disable-InboxRule, Enable-InboxRule, Set-Mailbox, Add-MailboxPermission, Add-RecipientPermission, Add-MailboxFolderPermission, Set-MailboxFolderPermission) | https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/new-inboxrule (same pattern for the others; raw folder: https://github.com/MicrosoftDocs/office-docs-powershell/tree/main/exchange/exchange-ps/ExchangePowerShell) | none shown |
| S14 | How to download logs in Microsoft Entra ID | https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-download-logs | ms.date 2024-11-08 |
| S15 | Microsoft Entra monitoring and health FAQ | https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reports-faq | ms.date 2025-05-06, updated 2026-06-15 |
| S16 | Learn about the sign-in log activity details | https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-in-log-activity-details | ms.date 2026-03-04 |
| S17 | Non-interactive user sign-ins | https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-noninteractive-sign-ins | ms.date 2026-02-09 |
| S18 | Customize and filter activity logs in Microsoft Entra ID | https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-customize-filter-logs | ms.date 2025-11-07 |
| S19a | Graph `signIn` resource, v1.0 | https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-1.0 | ms.date 2025-11-28 |
| S19b | Graph `signIn` resource, beta (plus `authenticationDetail`, `mfaDetail` beta pages) | https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-beta | ms.date 2025-11-27 |
| S19c | Graph sub-types `deviceDetail`, `signInLocation`, `geoCoordinates`, `signInStatus` | https://learn.microsoft.com/en-us/graph/api/resources/devicedetail?view=graph-rest-1.0 (same pattern for the others) | n/a |
| S20 | Graph `directoryAudit` and sub-types (`auditActivityInitiator`, `userIdentity`, `appIdentity`, `targetResource`, `modifiedProperty`), v1.0 | https://learn.microsoft.com/en-us/graph/api/resources/directoryaudit?view=graph-rest-1.0 | n/a |
| S21 | Microsoft Entra audit log activity reference | https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities | ms.date 2025-03-25 |
| S22 | View activity logs of application permissions | https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/app-perms-audit-logs | ms.date 2025-04-28 |
| S23 | Security operations playbook: compromised and malicious applications | https://learn.microsoft.com/en-us/security/zero-trust/security-operations-playbook-compromised-malicious-app | updated 2026-11-04 |
| S24 | Detect and remediate illicit consent grants | https://learn.microsoft.com/en-us/defender-office-365/detect-and-remediate-illicit-consent-grants | 2026-07-03 |
| S25 | Track and investigate identity activities with linkable identifiers | https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-authentication-track-linkable-identifiers | ms.date 2026-09-02 |
| S26 | Azure Monitor `SigninLogs` table reference | https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs | 2026-08-27 |
| S27 | Learn about the monitoring and health activity log schemas | https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-activity-log-schemas | ms.date 2025-05-27 |

Note: the requested page "Sign-in log schema in Azure Monitor" (`reference-azure-monitor-sign-ins-log-schema`) now
redirects to S27. S26 was used for the Azure Monitor column names instead.

---

## 1. Unified audit log (UAL)

### 1a. Purview portal "Audit" search export (CSV)

#### 1a-1 Four-column layout

- **Status:** CONFIRMED
- **Source:** S4 https://learn.microsoft.com/en-us/purview/audit-log-export-records (retrieved 2026-11-17)
- **Paraphrase:** When the exported CSV is opened in Excel Power Query, Microsoft says you see four columns. The
  event detail sits in `AuditData` as a JSON object. The names below are listed in this order in the prose; the
  page does not say it is the literal header order.

```text
CreationDate
UserIds
Operations
AuditData
```

#### 1a-2 Newer layout (RecordId, ..., AssociatedAdminUnitsNames)

- **Status:** UNCONFIRMED
- **Sources checked:** S4, S5, S6, S8, and https://learn.microsoft.com/en-us/purview/purview-admin-units (retrieved 2026-11-17)
- **Why unconfirmed:** No Microsoft page lists these headers. The current pages still describe the four-column
  layout above. A third-party blog (office365itpros.com, 2023-11-20) describes `AssociatedAdminUnits` as an array
  inside the AuditData payload, which is not Microsoft documentation.
- **Best knowledge (verify against a real export):**

```text
RecordId
CreationDate
RecordType
Operation
UserId
AuditData
AssociatedAdminUnits
AssociatedAdminUnitsNames
```

- **What S5 does document (CONFIRMED, UI labels only, not CSV headers):** the search-job detail grid shows these columns.

```text
Date (UTC)
IP Address
User
Record type
Activity
Item
Admin Units
Details
```

#### 1a-3 CreationDate text format

- **Status:** UNCONFIRMED
- **Why:** None of S4, S5, S6 states the text format of the exported `CreationDate`. S5 says dates in the search UI
  are in UTC.
- **Best knowledge:** ISO 8601 in UTC, for example `2024-05-01T12:34:56.0000000Z` in recent exports. Parsers should
  accept ISO 8601 with or without fractional seconds and `Z`, and should prefer `AuditData.CreationTime` (see 1c-2).

#### 1a-4 Export row limits and search-job facts

- **Status:** CONFIRMED
- **Sources:** S4 and S5 (retrieved 2026-11-17)
- **Paraphrase:**
  - Export holds at most 50,000 rows for Audit (Standard) and 1,000,000 rows for Audit (Premium) per search.
  - If a search returns more than that, the CSV silently leaves records out (S4). Microsoft advises narrower or split searches.
  - Search date range is at most 180 days per search (S5).
  - Up to 10 search jobs at once per user; completed jobs are kept 30 days (S5).
  - The job's "Total results" is approximate above 100,000 (S5).
  - The job detail total removes duplicates, so the item list can contain duplicates (S5). Deduplicate on
    `AuditData.Id`.
  - An admin scoped to administrative units only sees user-generated records inside those units (S5). An
    export made by such a "restricted admin" is therefore incomplete by design.
  - Retention: 180 days for Audit (Standard) records created on or after 2023-10-17 (90 days before that); one year
    by default for E5-licensed users' Entra, Exchange and SharePoint records (S5).
- **Unverified note:** search-engine snippets of other copies of S4 quoted 100,000 rows for Premium. The en-us pages
  read on 2026-11-17 both say 1,000,000. Older exports may have been capped lower.

### 1b. Search-UnifiedAuditLog piped to Export-Csv

#### 1b-1 Output object properties

- **Status:** PARTIAL
- **Sources:** S3, S4, S8, S9 (retrieved 2026-11-17)
- **CONFIRMED property names:** S4 selects `CreationDate,UserIds,RecordType,AuditData`. S9 lists the "primary"
  result properties. S3 names `ResultIndex`, `ResultCount` and `AuditSearchRequestMetadata.moreRecordsAvailable`.

```text
RecordType
CreationDate
UserIds
Operations
AuditData
ResultIndex
ResultCount
Identity
AuditSearchRequestMetadata   (S3 only, with a moreRecordsAvailable boolean; how it serializes to CSV is not documented)
```

- **UNCONFIRMED:** the following appear in real `Export-Csv` output (generic Exchange PowerShell object
  properties) but are not on any Microsoft page found. S3's OUTPUTS section is empty and no page gives the full
  header order.

```text
RunspaceId
IsValid
ObjectState
```

- **Other notes:**
  - S9 types `CreationDate` as DateTime with a US-style example (`11/17/2025 2:30:15 PM`). S9's sample pairs it
    with an AuditData `CreationTime` of the same clock time, which suggests UTC, but no page says so. When
    `Export-Csv` writes a DateTime, the text format follows the PowerShell session culture (inference, UNCONFIRMED).
    Prefer `AuditData.CreationTime`.
  - S9 calls `Identity` a GUID that uniquely identifies the record. Whether it equals `AuditData.Id` is UNCONFIRMED.
  - Whether the top-level `RecordType` comes out as a name (`ExchangeAdmin`) or an integer is UNCONFIRMED. S3's
    `-Formatted` switch turns integer `RecordType` and `Operation` values into descriptive strings, so accept both.

#### 1b-2 ResultIndex and ResultCount

- **Status:** CONFIRMED (with a wording CONFLICT)
- **Sources:** S3, S8, S9 (retrieved 2026-11-17)
- **Paraphrase:** `ResultCount` is the total number of hits for the query across all pages of a session.
  `ResultIndex` is the record's running position in that result set. S8's sample script treats retrieval as
  finished when the last record's `ResultIndex` equals `ResultCount`. S3 describes `ResultIndex` loosely as hits in
  the current iteration, while S9 calls it the position in the results; S8's code supports the position reading.

#### 1b-3 Limits and SessionCommand behaviour

- **Status:** CONFIRMED
- **Sources:** S3, S8 (retrieved 2026-11-17)

```text
-ResultSize <Int32>          default 100, maximum 5000
-SessionId <String>          any string; reuse it to page through one query
-SessionCommand ReturnLargeSet
-SessionCommand ReturnNextPreviewPage
-Formatted
-HighCompleteness            (preview)
```

- **Paraphrase:**
  - By default the cmdlet returns up to 100 records. S3 says `-SessionCommand` is required to get more than 100,
    yet Microsoft's own MailItemsAccessed examples (S10) use `-ResultSize 1000` without it. Treat the S3 wording
    as imprecise.
  - `ReturnLargeSet` returns unsorted data and allows paging up to 50,000 results per session.
  - `ReturnNextPreviewPage` returns data sorted by date, capped at 5,000 records in total.
  - Switching between the two values on one SessionId caps the output at 10,000.
  - S8: each run is limited to 50,000 records. A result of exactly 50,000 means records were probably missed, so split the date range.
  - Dates given without a time zone are read as UTC.
  - `-HighCompleteness` trades speed for completeness; without it some results may be missing.

### 1c. AuditData JSON: common schema

#### 1c-1 Common fields

- **Status:** CONFIRMED (`Version` only in S6)
- **Sources:** S1 "Common schema", S6 (retrieved 2026-11-17)

```text
Id
RecordType
CreationTime
Operation
OrganizationId
UserType
UserKey
Workload
ResultStatus
ObjectId
UserId
ClientIP
Scope
AppAccessContext
Version          (S6 lists it; S1's common-schema table does not)
```

- **Paraphrase of the parts that matter for parsing:**
  - `ResultStatus`: documented values are `Succeeded`, `PartiallySucceeded`, `Failed`; Exchange admin records use
    `True`/`False`. Workloads may overwrite the meaning. For Entra STS logons, `Succeeded` only means the HTTP call
    worked, not the logon; use `LogonError`/`ErrorCode` (see 1g).
  - `ClientIP` can be the IP of a trusted Microsoft app acting for the user. For Entra ID events it is not logged and is `null`.
  - `UserKey`: **CONFLICT.** S1 says it carries a PUID for SharePoint, OneDrive and Exchange users; S6 says it
    carries the Entra object ID (GUID or hex) and gives per-UserType values.
  - `UserType` enum (S1): `0 Regular`, `1 Reserved`, `2 Admin`, `3 DCAdmin`, `4 System`, `5 Application`,
    `6 ServicePrincipal`, `7 CustomPolicy`, `8 SystemPolicy`, `9 PartnerTechnician`, `10 Guest`. S6 adds `11 Agent`.
    For Entra events, admins are logged as `0` (S1, S6).
  - `Scope` enum: `0 Online`, `1 Onprem`.
  - `ResultStatus` casing **CONFLICT:** S1 `Succeeded`/`Failed`; S2 samples `success`/`failed`; S9 samples `Success`.

#### 1c-2 CreationTime format

- **Status:** CONFIRMED that it is UTC; offset suffix is a CONFLICT
- **Sources:** S1, S2, S9 (retrieved 2026-11-17)
- **Paraphrase:** S1 types it `Edm.Date` and says it is the UTC time the record was generated. Microsoft's sample
  JSON shows no offset and no fractional seconds (`2015-06-29T20:03:19` in S2, `2025-11-17T14:30:15` in S9), but
  S9's own field table shows `2025-11-17T14:30:15Z`. Fractional seconds are not documented (UNCONFIRMED).
  Treat a value without an offset as UTC; accept `Z` and fractions.

#### 1c-3 RecordType integer enum

- **Status:** CONFIRMED
- **Source:** S1 "Enum: AuditLogRecordType" (retrieved 2026-11-17)

```text
1   ExchangeAdmin
2   ExchangeItem
3   ExchangeItemGroup
4   SharePoint
6   SharePointFileOperation
7   OneDrive
8   AzureActiveDirectory
9   AzureActiveDirectoryAccountLogon      (S1 marks it deprecated)
14  SharePointSharingOperation
15  AzureActiveDirectoryStsLogon
19  ExchangeAggregatedOperation
36  SharePointListOperation
50  ExchangeItemAggregated                (S1 ties it to MailItemsAccessed)
```

- **Paraphrase:** `2` is single-item mailbox actions (create, receive), `3` is actions on several items (move,
  delete), `50` is MailItemsAccessed, `15` is Entra STS logon events.
- **CONFLICT:** S9's descriptive table types `RecordType` as a string with names and maps MailItemsAccessed to
  `ExchangeAggregatedOperation`, but S9's own MailItemsAccessed sample uses `50`, and every sample in S2 and S9
  uses integers. Follow S1. Accept integer or name.

#### 1c-4 AppAccessContext

- **Status:** CONFIRMED (shape is UNCONFIRMED)
- **Source:** S1 "Complex Type AppAccessContext" (retrieved 2026-11-17)

```text
AADSessionId
APIId
ClientAppId
ClientAppName
CorrelationId
UniqueTokenId
IssuedAtTime
```

- **Paraphrase:** `AADSessionId` is the Entra session ID of the sign-in the app used for the user. `UniqueTokenId`
  is set when an Entra token is available, is unique per token, and is case-sensitive. `IssuedAtTime` is when that
  token's authentication happened. `ClientAppId`/`ClientAppName` identify the Entra app acting for the user.
  `APIId` identifies the API path (for example Graph).
- **UNCONFIRMED:** S1 types the field `CollectionSelf.[AppAccessContext]`. Real records show a single JSON object;
  accept an object or an array. The text format of `IssuedAtTime` is not documented.

#### 1c-5 Shared complex types (Name/Value and ModifiedProperty)

- **Status:** CONFIRMED
- **Sources:** S1 (NameValuePair entries have a Name and a Value; S2 sample `ExtendedProperties`), S6
  ("ModifiedProperties (Name, NewValue, OldValue)") (retrieved 2026-11-17)

```text
NameValuePair:     {"Name": ..., "Value": ...}
ModifiedProperty:  {"Name": ..., "NewValue": ..., "OldValue": ...}
```

### 1d. Exchange admin records (RecordType 1)

#### 1d-1 Exchange Admin schema

- **Status:** CONFIRMED
- **Sources:** S1 "Exchange Admin schema", S7 "Exchange admin activities" (retrieved 2026-11-17)

```text
ModifiedObjectResolvedName
Parameters
ModifiedProperties
ExternalAccess
OriginatingServer
OrganizationName
DeviceId
TokenObjectId
TokenTenantId
```

- **Paraphrase:** `Operation` holds the cmdlet name. `Parameters` is a Name/Value list of the parameters actually
  used. `ObjectId` is the object the cmdlet changed. `ResultStatus` is `True`/`False`. `ExternalAccess` is true when
  Microsoft datacenter staff, a service account or a delegated admin ran it. S7: every state-changing cmdlet is
  logged except `Get-`, `Search-` and `Test-` verbs; a few noisy service cmdlets are not logged; entries can take
  up to 30 minutes to appear.

#### 1d-2 New-InboxRule and Set-InboxRule in the UAL

- **Status:** CONFIRMED
- **Sources:** S7 (both listed as mailbox activities done in Outlook on the web), S9 (sample and RecordType table)
  (retrieved 2026-11-17)
- **Paraphrase:** S9 shows `New-InboxRule` with `RecordType` 1 and a `Parameters` array of Name/Value pairs
  whose Names are cmdlet parameter names. S9's table maps `New-InboxRule`, `Set-InboxRule` and `Set-Mailbox` to
  `ExchangeAdmin`. Skeleton (not Microsoft's sample):

```text
"Operation": "New-InboxRule"
"RecordType": 1
"ObjectId": <rule identity>
"Parameters": [ {"Name": <cmdlet parameter name>, "Value": <string>}, ... ]
```

#### 1d-3 Inbox rule parameter names

- **Status:** CONFIRMED as cmdlet parameter names; PARTIAL for how they appear in `Parameters`
- **Source:** S13 New-InboxRule and Set-InboxRule (retrieved 2026-11-17)

```text
Name
Identity                     (Set-InboxRule; also Remove-, Disable-, Enable-InboxRule)
Mailbox
ForwardTo
RedirectTo
ForwardAsAttachmentTo
DeleteMessage
SoftDeleteMessage
PermanentDelete
MoveToFolder
CopyToFolder
MarkAsRead
SubjectContainsWords
SubjectOrBodyContainsWords
BodyContainsWords
From
FromAddressContainsWords
SentTo
StopProcessingRules
AlwaysDeleteOutlookRulesBlob
Force
```

- **UNCONFIRMED:** how values are serialized in `Parameters[].Value` (separator for multi-valued parameters such
  as `ForwardTo` or `SubjectContainsWords`, how switch parameters show, whether addresses carry a prefix). Real
  records commonly use `;` between values and `True` for switches. Do not hard-code a separator.

#### 1d-4 UpdateInboxRules (Outlook client rule changes)

- **Status:** Operation name CONFIRMED; rule detail fields UNCONFIRMED
- **Sources:** S7 (operation), S1 Exchange Mailbox schema (`OperationProperties` container) (retrieved 2026-11-17)
- **Paraphrase:** `UpdateInboxRules` is a mailbox-audit action logged when an inbox rule is created, changed or
  removed from the Outlook client. It is not an admin cmdlet, so it has no `Parameters` array.
- **UNCONFIRMED:** the rule details inside `OperationProperties` (names such as `RuleName`, `RuleActions`,
  `RuleCondition`, `RuleOperation` are seen in practice). No Microsoft page documents them. The RecordType
  (`2` in practice) is also undocumented.

#### 1d-5 Set-Mailbox forwarding

- **Status:** CONFIRMED (parameter names; RecordType 1 via S9 table)
- **Sources:** S13 Set-Mailbox, S9 (retrieved 2026-11-17)

```text
Identity
ForwardingSmtpAddress
ForwardingAddress
DeliverToMailboxAndForward
GrantSendOnBehalfTo
```

- **UNCONFIRMED:** the value format in the record (for example whether `ForwardingSmtpAddress` carries `smtp:`).

#### 1d-6 Mailbox permission cmdlets

- **Status:** CONFIRMED (parameter names); RecordType UNCONFIRMED
- **Sources:** S13, S7, S1 (retrieved 2026-11-17)

```text
Add-MailboxPermission:        Identity, User, AccessRights, InheritanceType, AutoMapping, Owner, Instance, Deny, GroupMailbox, IgnoreDefaultScope
Add-RecipientPermission:      Identity, Trustee, AccessRights
Add-MailboxFolderPermission:  Identity, User, AccessRights, SharingPermissionFlags, SendNotificationToUser
Set-MailboxFolderPermission:  Identity, User, AccessRights, SharingPermissionFlags, SendNotificationToUser
```

- **Paraphrase:** S7 lists `Add-MailboxPermission` and `Remove-MailboxPermission` (FullAccess delegation) as audited
  activities and warns that system accounts (for example `NT AUTHORITY\SYSTEM` and an
  `NT SERVICE\MSExchangeAdminApiNetCore(...)` account) also produce them during maintenance. `Add-RecipientPermission`
  is not named on S7 but falls under the general admin-cmdlet logging rule (PARTIAL). Folder permissions changed
  through the mailbox (not the cmdlet) are separate mailbox-audit operations `AddFolderPermissions`,
  `ModifyFolderPermissions`, `RemoveFolderPermissions` (S7); S1's `ExchangeFolder` type carries `MemberSid`,
  `MemberRights`, `MemberUpn` for them.
- **UNCONFIRMED:** RecordType for these cmdlets (`ExchangeAdmin` in practice).

### 1e. Exchange mailbox records and MailItemsAccessed

#### 1e-1 Exchange Mailbox schema

- **Status:** CONFIRMED
- **Source:** S1 "Exchange Mailbox schema" and sub-types (retrieved 2026-11-17)

```text
LogonType
InternalLogonType
MailboxGuid
MailboxOwnerUPN
MailboxOwnerSid
MailboxOwnerMasterAccountSid
LogonUserSid
LogonUserDisplayName
ExternalAccess
OriginatingServer
OrganizationName
ClientInfoString
ClientIPAddress
ClientMachineName
ClientProcessName
ClientVersion
SessionId
AppId
ClientAppId
HostAppId
OperationProperties
ClientRequestId
ExternalUserTenantId
ActorIP
ActorInfoString
DeviceId
CloudInstanceName
TokenObjectId
TokenTenantId
AuthType
TokenType
recipientCount        (lower-case first letter as documented)
recipientList         (lower-case first letter as documented)
```

```text
LogonType enum: 0 Owner, 1 Admin, 2 Delegated, 3 Transport, 4 SystemService, 5 BestAccess, 6 DelegatedAdmin

ExchangeMailboxAuditGroupRecord (multi-item): Folder, CrossMailboxOperations, DestMailboxId, DestMailboxOwnerUPN,
  DestMailboxOwnerSid, DestMailboxOwnerMasterAccountSid, DestFolder, Folders, AffectedItems, Teams

ExchangeMailboxAuditRecord (single item): Item, ModifiedProperties, MbxLoginLocalQueueADLookupInfo, SendAsUserSmtp,
  SendAsUserMailboxGuid, SendOnBehalfOfUserSmtp, SendOnBehalfOfUserMailboxGuid, ContactEmail1EmailAddress,
  ContactEmail1DisplayName, ContactEmail2EmailAddress, ContactEmail2DisplayName, ContactEmail3EmailAddress,
  ContactEmail3DisplayName, AttachmentId, AttachmentSizeInBytes, SaveToSentItems, Teams

ExchangeItem:   Id, Subject, ParentFolder, ParentMessage, Attachments, ImmutableId, InternetMessageId, ComplianceLabel,
                IsRecord, IsPriorityCleanup, SizeInBytes, Sensitivity
ExchangeFolder: Id, Path, Name, MemberSid, MemberRights, MemberUpn
```

- **Paraphrase:** `ClientIPAddress` is the client device IP (IPv4 or IPv6) and exists alongside the common
  `ClientIP`. `SessionId` is described as a session identifier that helps tell attacker actions from normal use.
  `ClientAppId` is the original calling service or protocol; `HostAppId` is the executing one.
- **Important difference:** in single-item mailbox records S1 types `ModifiedProperties` as a list of strings
  (property names), not the Name/NewValue/OldValue objects used by admin and Entra records.

#### 1e-2 MailItemsAccessed

- **Status:** CONFIRMED (IsThrottled: CONFIRMED in older training content only)
- **Sources:** S1, S10, S11 (retrieved 2026-11-17)

```text
RecordType 50 (ExchangeItemAggregated)

ExchangeAggregatedMailboxAuditRecord: OperationCount, Folders, Messages
ExchangeAggregatedFolder:             Id, Path, FolderItems
ExchangeFolderItem:                   Id, ImmutableId, InternetMessageId, CreationTime, Subject, SizeInBytes,
                                      Sensitivity, ClientRequestId, Teams
ExchangeAggregatedMessage:            Id, Path, MessageItems
ExchangeMessageItem:                  Id, SizeInBytes

OperationProperties entries:
  {"Name": "MailAccessType", "Value": "Bind"}   or   {"Name": "MailAccessType", "Value": "Sync"}
  {"Name": "IsThrottled", "Value": "True"}       (S11 only)
```

- **Paraphrase:**
  - Bind = access to one message. Binds within a 2-minute window are merged into one record. Each message is listed
    by `InternetMessageId` under `Folders`, and `OperationCount` gives the number of merged binds (S10).
  - Sync = a client downloading a folder. It is recorded per folder, and only for Outlook desktop on Windows or Mac.
    Every item in a synced folder should be treated as exposed (S10).
  - **CONFLICT:** S7's activity description says sync records come from mail protocols such as Exchange ActiveSync
    or IMAP, while S10 says sync is recorded only for Outlook desktop. Do not infer the client from `MailAccessType`
    alone; use `ClientInfoString`.
  - Duplicate binds of the same message within an hour are dropped, and syncs are filtered at one-hour intervals.
    A new record is still written if client IP, client info string, parent folder, logon type, access type,
    mailbox, user or session differ (S10).
  - S10's dedupe table uses descriptive labels (`Logon_type`, `MailboxUPN`, `User`) that are not the JSON keys
    (`LogonType`, `MailboxOwnerUPN`, `UserId`). Use the S1 key names.
  - S10 names `ClientInfoString`, `ClientIPAddress`, `SessionId` and `UserId` as the context fields for comparing
    attacker and user activity.
  - Throttling (S11, 2023 training unit): if a mailbox produces more than 1,000 MailItemsAccessed records in under
    24 hours, bind auditing stops for 24 hours and a record carries `IsThrottled` = `True`. **The current S10 article
    (2026-06-24) no longer mentions throttling**, so whether this still applies is UNCONFIRMED.

#### 1e-3 Mailbox operation names

- **Status:** CONFIRMED
- **Source:** S7 "Exchange mailbox activities" (retrieved 2026-11-17)

```text
MailItemsAccessed
Send
SendAs
SendOnBehalf
SoftDelete
HardDelete
MoveToDeletedItems
Move
Copy
Create
Update
FolderBind
MessageBind
MailboxLogin
AttachmentAccess
SearchQueryInitiated
UpdateInboxRules
UpdateCalendarDelegation
New-InboxRule
Set-InboxRule
Add-MailboxPermission
Remove-MailboxPermission
AddFolderPermissions
ModifyFolderPermissions
RemoveFolderPermissions
```

- **Paraphrase:** `Send` covers send, reply and forward. `SendAs`/`SendOnBehalf` are sends by another user using
  those permissions. `MoveToDeletedItems` is a move to Deleted Items. `SoftDelete` is a delete from Deleted Items
  (or Shift+Delete) into Recoverable Items. `HardDelete` is a purge from Recoverable Items.
- **CONFLICT:** S9 describes `SoftDelete` as a move to Deleted Items and maps SoftDelete, HardDelete, Move and Send
  to `ExchangeItem` (2). S1's enum text implies multi-item moves and deletes are `ExchangeItemGroup` (3). Key on
  `Operation`, not RecordType, and accept both the `Item` and the `AffectedItems` shapes.

### 1f. SharePoint and OneDrive records

#### 1f-1 SharePoint Base schema

- **Status:** CONFIRMED
- **Source:** S1 "SharePoint Base schema" (retrieved 2026-11-17)

```text
Site
ItemType
EventSource
SourceName
UserAgent
MachineDomainInfo
MachineId
ListItemUniqueId
ListId
ApplicationId
ApplicationDisplayName
IsWorkflow
```

```text
ItemType enum (S1):    0 Invalid, 1 File, 5 Folder, 6 web, 7 Site, 8 Tenant, 9 DocumentLibrary, 11 Page
EventSource enum (S1): 0 SharePoint, 1 ObjectModel
```

- **Paraphrase:** `ItemType` and `EventSource` are typed as strings that reference the enums, so values appear as
  names. `UserAgent` is supplied by the client. `ListItemUniqueId` and `ListId` are present only when applicable.
- **CONFLICT (casing):** S1 lists `web`; S6 lists `File`, `Folder`, `Web`, `Site`, `Tenant`, `DocumentLibrary`.

#### 1f-2 SharePoint file operations schema

- **Status:** CONFIRMED
- **Sources:** S1 "SharePoint file operations", S6 (retrieved 2026-11-17)

```text
SiteUrl
SourceRelativeUrl
SourceFileName
SourceFileExtension
DestinationRelativeUrl
DestinationFileName
DestinationFileExtension
UserSharedWith
SharingType
SourceLabel
DestinationLabel
SensitivityLabelOwnerEmail
SensitivityLabelId
```

- **Paraphrase:** `SiteUrl` + `SourceRelativeUrl` + `SourceFileName` equals `ObjectId` (the full path).
  `SourceFileExtension` is blank for folders. The Destination fields appear only for FileCopied and FileMoved.
  The prose spells some names differently (`SiteURL`, `SourceRelativeURL`, `ObjectID`); use the table spellings above.

#### 1f-3 SharePoint Sharing schema

- **Status:** CONFIRMED (value list is a CONFLICT)
- **Sources:** S1 "SharePoint Sharing schema", S12 (retrieved 2026-11-17)

```text
TargetUserOrGroupName
TargetUserOrGroupType
EventData
SiteUrl
SourceRelativeUrl
SourceFileName
SourceFileExtension
UniqueSharingId
```

- **Paraphrase:** `TargetUserOrGroupName` is the UPN or name of who received access. `EventData` carries follow-up
  detail (for example group membership or permission level).
- **CONFLICT:** `TargetUserOrGroupType` values are `Member`, `Guest`, `Group`, `Partner` in S1, but `Member`, `Guest`,
  `SharePointGroup`, `SecurityGroup`, `Partner` in S12.

#### 1f-4 SharePoint/OneDrive operation names

- **Status:** CONFIRMED
- **Sources:** S7, S1 SharePointAuditOperation enum, S12 (retrieved 2026-11-17)

```text
FileAccessed
FileDownloaded
FileSyncDownloadedFull
FileSyncUploadedFull
FileUploaded
FilePreviewed
FileModified
FileDeleted
AnonymousLinkCreated
AnonymousLinkUpdated
AnonymousLinkRemoved
AnonymousLinkUsed
CompanyLinkCreated
CompanyLinkRemoved
CompanyLinkUsed
SharingInvitationCreated
SharingInvitationAccepted
SharingSet
SharingRevoked
SecureLinkCreated
SecureLinkDeleted
SecureLinkUsed
AddedToSecureLink
RemovedFromSecureLink
AddedToGroup
```

- **Paraphrase:**
  - `FileAccessed` is not logged again for the same user and file for 5 minutes (S7).
  - `FileSyncDownloadedFull` is a download through the OneDrive sync app; `FileSyncDownloadedPartial` is deprecated.
  - `SharingSet` is sharing with someone already in the directory, usually alongside `AddedToGroup`.
  - `SharingInvitationCreated` is for an external user not in the directory; S12 says it is logged only when the
    shared resource is a site.
  - `SecureLinkCreated` ("specific people" link) is paired with `AddedToSecureLink`, whose `TargetUserOrGroupName`
    names the recipient; the two have nearly identical timestamps (S12).
  - `AnonymousLinkUsed` may lack a user identity but has the IP (S7).
  - `Workload` values `SharePoint` and `OneDrive` appear in S9's table.

### 1g. Microsoft Entra ID records in the UAL

#### 1g-1 Entra schemas inside AuditData

- **Status:** CONFIRMED (one spelling CONFLICT)
- **Sources:** S1 Azure Active Directory sections, S2 sample, S6 (retrieved 2026-11-17)

```text
Base:          AzureActiveDirectoryEventType, ExtendedProperties, ModifiedProperties
               AzureActiveDirectoryEventType: 0 = AccountLogon (sign-in), 1 = AzureApplicationAuditEvent (S6 numbers, S1 names)

Directory:     Actor, ActorContextId, ActorIpAddress, InterSystemsId, IntraSystemsId, SupportTicketId, Target, TargetContextId
               IdentityTypeValuePair: ID, Type
               IdentityType names: Claim, Name, Other, PUID, SPN, UPN

STS logon:     ApplicationId, Client, DeviceProperties, ErrorCode, LogonError

Account logon: Application, Client, LoginStatus, UserDomain     (RecordType 9, deprecated)
```

- **CONFLICT:** S1's table spells `IntraSystemsId`; S2's sample JSON spells `IntraSystemId`. Real records use
  `IntraSystemId` (best knowledge). Accept both.
- **CONFLICT:** S2's sample "Add User." directory record carries `AzureActiveDirectoryEventType` 0, which S6 defines
  as a sign-in. Do not classify Entra records by this field; use `RecordType` and `Operation`.
- **PARTIAL:** S1 gives no numbers for IdentityType. S2's sample uses `Type` 2 for a GUID, 3 for a PUID and 5 for a
  UPN, which fits 0-based alphabetical order (Claim=0 ... UPN=5). This is an inference.

#### 1g-2 UserLoggedIn / UserLoginFailed fields

- **Status:** mixed, see each line
- **Sources:** S1, S7, Microsoft Q&A threads (not documentation) (retrieved 2026-11-17)
  - `UserLoginFailed`: CONFIRMED as an Operation in S1 (ErrorCode description).
  - `UserLoggedIn`: CONFIRMED as an Operation in S7.
  - RecordType 15 `AzureActiveDirectoryStsLogon` for these: PARTIAL. S1 ties UserLoginFailed to the STS logon schema; no page states the RecordType for UserLoggedIn.
  - `ErrorCode`: CONFIRMED. It holds the AADSTS code for failures, and `0` means success (S1).
  - `LogonError`: CONFIRMED. It is a readable failure reason (S1).
  - `ErrorNumber`: UNCONFIRMED. No Microsoft page found; S1 documents `ErrorCode` instead. Real STS records commonly carry `ErrorNumber`. Accept both.
  - `ActorIpAddress`: CONFIRMED in the Directory schema. Because `ClientIP` is null for Entra events (S1), use it for the IP.
  - `InterSystemsId`, `ApplicationId`: CONFIRMED.
  - `ResultStatus`: CONFIRMED caveat. For STS logons it reflects the HTTP call, not the logon outcome (S1).
  - `DeviceProperties`: PARTIAL. S1 describes the contents in prose: Id, display name, OS, browser,
    IsCompliant, IsCompliantAndManaged, SessionId, and DeviceTrustType (0 = Entra registered, 1 = Entra joined,
    2 = hybrid joined). The exact Name strings are UNCONFIRMED. Best knowledge: `Id`, `DisplayName`, `OS`,
    `BrowserType`, `IsCompliant`, `IsCompliantAndManaged`, `SessionId`, `TrustType`.
  - `ExtendedProperties` keys: UNCONFIRMED. Best knowledge: `ResultStatusDetail`, `UserAgent`, `RequestType`,
    `KeepMeSignedIn`, `UserAuthenticationMethod`. S6 only says the field holds extended properties. Microsoft Q&A
    questions about `RequestType` values went unanswered by documentation.

#### 1g-3 Directory operation names (trailing period)

- **Status:** CONFIRMED for the first list; base names CONFIRMED but the UAL form UNCONFIRMED for the second list
- **Sources:** S7 (UAL operation strings), S21, S22, S23, S24 (Entra activity names) (retrieved 2026-11-17)
- **Paraphrase:** S7 shows that Entra-sourced UAL operations end with a period. S2's sample even capitalises one
  differently (`Add User.`), so compare case-insensitively.

CONFIRMED UAL operation strings (S7):

```text
Add user.
Update user.
Delete user.
Change user password.
Reset user password.
Set force change user password.
Change user license.
Set license properties.
Add member to role.
Remove member from role.
Add service principal.
Remove service principal.
Add service principal credentials.
Remove service principal credentials.
Add delegation entry.
Set delegation entry.
Remove delegation entry.
```

Entra activity names CONFIRMED without the period (S21, S22). The UAL form with a trailing period is UNCONFIRMED
(it matches the S7 pattern and is seen in practice):

```text
Consent to application
Add delegated permission grant
Add app role assignment to service principal
Add service principal
User registered security info
User changed default security info
User deleted security info
Update user
Register device
Add registered owner to device
```

- **UNCONFIRMED:** `Add app role assignment grant to user` (and its `.` form). It does not appear in any Microsoft
  page found; S21 has `Add app role assignment to service principal` and `Add app role assignment to group`. It
  appears in third-party detection content only.
- S24 confirms that a Purview audit search surfaces a "Consent to application" activity with an IsAdminConsent flag.

#### 1g-4 Consent details in ModifiedProperties

- **Status:** CONFIRMED in Entra directoryAudit; UNCONFIRMED in the UAL
- **Sources:** S23 (directoryAudit sample and Modified Properties guidance), S24, S6 (retrieved 2026-11-17)

```text
ConsentContext.IsAdminConsent
ConsentAction.Permissions
```

- **Paraphrase:** S23 shows a "Consent to application" directoryAudit entry whose `targetResources[].modifiedProperties`
  includes `ConsentContext.IsAdminConsent` with a `newValue` that is a JSON-encoded string (the word True wrapped
  in escaped quotes). It tells analysts to review `ConsentAction.Permissions` under Modified Properties. S24: True
  means an admin granted tenant-wide consent.
- **UNCONFIRMED:**
  - That UAL `ModifiedProperties[].Name` uses the same strings. This is expected, since the UAL copies Entra audit
    events, and it is seen in practice.
  - Further names seen in practice: `ConsentContext.IsAppOnly`, `ConsentContext.OnBehalfOfAll`,
    `ConsentContext.Tags`, `ConsentAction.Reason`, `TargetId.ServicePrincipalNames`,
    `DelegatedPermissionGrant.Scope`, `DelegatedPermissionGrant.ConsentType`, `AppRole.Value`.
  - The `ConsentAction.Permissions` value is a free-text dump of the grant (scope list, consent type, IDs). Its
    layout is undocumented, so parse it defensively.

---

## 2. Microsoft Entra sign-in logs

### 2a. Entra admin center "Download" (CSV)

#### 2a-1 What Microsoft documents about the download

- **Status:** CONFIRMED
- **Sources:** S14, S15, S16, S17 (retrieved 2026-11-17)
- **Paraphrase:**
  - Formats are CSV and JSON. Timestamps in downloaded files are UTC (S14). The portal UI shows local time (S15, S16).
  - Up to 100,000 sign-in (or provisioning) records per file and 250,000 audit records per file (S14). S15 frames
    these as sizes that work reliably, varying with the number of fields; larger sets may time out.
  - The downloaded columns are fixed. UI column choices do not change them, but active filters do limit the rows (S14, S15).
  - The CSV leaves out data that Graph represents as nested arrays, such as Conditional Access policy results
    and report-only results (S15).
  - The user may type a custom file name for each file (S14), so file names cannot be trusted as metadata.
  - Duplicate entries for one Request ID can occur: risk re-publication, MFA aggregation, retried batches, or
    multiple Conditional Access policies (S15).
  - Cross-tenant sign-ins may be redacted, with `.XXX` in the IP or "PII Removed" in device details (S15).
  - Non-interactive sign-ins are grouped in the UI when Application, User, IP address, Status and Resource ID
    match (S17). For confidential clients, the IP shown is the IP of the original token issue, not of the refresh (S17).
  - Retention is 7 to 30 days depending on licence (S15).
- **Download choices for sign-in logs (S14):**

```text
Interactive sign-ins
Interactive sign-ins with only the authentication details included
Non-interactive sign-ins
Non-interactive sign-ins with only the authentication details included
Application sign-ins
Managed identity
```

- **Unverified note:** search-engine snippets of older doc versions cite 250,000 for sign-in downloads. The pages
  read on 2026-11-17 say 100,000.

#### 2a-2 CSV column headers (interactive and non-interactive)

- **Status:** UNCONFIRMED (header row); PARTIAL (UI labels)
- **Why:** no Microsoft page lists the CSV header row. Microsoft does document UI labels, and those labels
  disagree in casing between pages, so header matching must be case-insensitive.
- **UI labels documented by Microsoft (PARTIAL):**

```text
S16 details pane: User, Username, User ID, Sign-in identifier, User type, Authentication requirement, Client app,
                  Client credential type, Continuous access evaluation, Application, Application ID, Resource,
                  Resource ID, Resource tenant ID, Resource service principal ID, Correlation ID, Request ID,
                  Unique token identifier
S25 mapping:      User ID, Resource Tenant ID, Session ID, Device ID, Unique Token Identifier, Date
S18 filters:      Request ID, Correlation ID, User, Application, Status, Resource, IP address, Conditional Access,
                  Is Agent, Agent type
S17 extra:        Resource ID, Number of grouped sign-ins (non-interactive view)
```

- **Best-knowledge header list from real exports (UNCONFIRMED, verify against a sample; order and casing not
  guaranteed):**

```text
Date (UTC)
Request ID
User agent
Correlation ID
User ID
User
Username
User type
Cross tenant access type
Incoming token type
Authentication Protocol
Unique token identifier
Original transfer method
Client credential type
Token issuer type
Token issuer name
Latency
Application
Application ID
Resource
Resource ID
Resource tenant ID
Home tenant ID
Home tenant name
IP address
Location
Status
Sign-in error code
Failure reason
Client app
Device ID
Browser
Operating System
Compliant
Managed
Join Type
Multifactor authentication result
Multifactor authentication auth method
Multifactor authentication auth detail
Authentication requirement
Sign-in identifier
Session ID
IP address (seen by resource)
Through Global Secure Access
Global Secure Access IP address
Autonomous system number
Flagged for review
Token Protection - Sign In Session
Conditional Access
Managed Identity type
Associated Resource Id
Federated Token Id
Federated Token Issuer
```

- **Status values (CONFIRMED as UI filter values, S18):** `Success`, `Failure`, `Interrupted`.
- **Client app values (CONFIRMED as UI filter names, S18):** `Browser`, `Mobile apps and desktop clients`,
  `Authenticated SMTP`, `Autodiscover`, `Exchange ActiveSync`, `Exchange Online PowerShell`,
  `Exchange Web Services`, `IMAP4`, `MAPI over HTTP`, `Offline Address Book`, `Outlook Anywhere (RPC over HTTP)`,
  `Outlook Service`, `POP3`, `Reporting Web Services`, `Other clients`. The exact strings in exported data are
  UNCONFIRMED; for example `Mobile Apps and Desktop clients` is commonly seen with different casing.

#### 2a-3 Authentication details CSV

- **Status:** UNCONFIRMED
- **Why:** S14 confirms the "authentication details" download variants exist, but no page lists their columns or
  how they join back to the sign-in rows.
- **Related CONFIRMED Graph names (S19b `authenticationDetail`, beta):**

```text
authenticationMethod
authenticationMethodDetail
authenticationStepDateTime
authenticationStepRequirement
authenticationStepResultDetail
succeeded
```

- Best knowledge: friendly-name versions of these fields plus a key (Request ID or Correlation ID) to join to
  the sign-in row. Not verified.

#### 2a-4 File names

- **Status:** UNCONFIRMED
- **Why:** not documented, and S14 lets the user override the name.
- **Best knowledge:** `InteractiveSignIns_<start>_<end>.csv`, `InteractiveSignIns_AuthDetails_<start>_<end>.csv`,
  `NonInteractiveSignIns_<start>_<end>.csv`, `NonInteractiveSignIns_AuthDetails_<start>_<end>.csv`,
  `ApplicationSignIns_<start>_<end>.csv`, `MSISignIns_<start>_<end>.csv`. Detect file type from headers, never from
  the name.

#### 2a-5 Date and Location columns

- **Status:** UNCONFIRMED (CSV text formats); CONFIRMED (that timestamps are UTC, S14)
- **Best knowledge:** the date column is ISO 8601 UTC with `Z` (for example `2024-01-31T23:59:59Z`). `Location` is a
  comma-joined `City, State, CC` string that can be partly empty. Verify against a sample.
- **CONFIRMED related shapes:** in Graph, `location` is an object with `city`, `state`, `countryOrRegion` (two-letter
  code) and `geoCoordinates` (S19c). In Azure Monitor `SigninLogs`, `Location` is only the two-letter country code
  and `LocationDetails` holds the rest (S26). These are different surfaces from the admin-center CSV.

### 2b. JSON download and the Graph `signIn` resource

#### 2b-1 JSON download layout

- **Status:** UNCONFIRMED
- **Why:** S14 confirms JSON is offered but does not define its layout.
- **Best knowledge:** an array of camelCase objects resembling the Graph beta `signIn` resource. S27 warns that v1.0
  and beta differ and that Azure Monitor schemas can differ from Graph.

#### 2b-2 signIn v1.0 properties

- **Status:** CONFIRMED
- **Source:** S19a (retrieved 2026-11-17)

```text
appDisplayName
appId
appliedConditionalAccessPolicies
clientAppUsed
conditionalAccessStatus
correlationId
createdDateTime
deviceDetail
id
ipAddress
isInteractive
location
resourceDisplayName
resourceId
riskDetail
riskEventTypes_v2
riskLevelAggregated
riskLevelDuringSignIn
riskState
status
userDisplayName
userId
userPrincipalName
```

(`riskEventTypes` also appears in v1.0's JSON representation block but not in its property table.)

#### 2b-3 signIn beta properties

- **Status:** CONFIRMED
- **Source:** S19b (retrieved 2026-11-17)

```text
agent
appDisplayName
appId
appliedConditionalAccessPolicies
appOwnerTenantId
appliedEventListeners
appTokenProtectionStatus
authenticationAppDeviceDetails
authenticationAppPolicyEvaluationDetails
authenticationContextClassReferences
authenticationDetails
authenticationMethodsUsed
authenticationProcessingDetails
authenticationProtocol
authenticationRequirement
authenticationRequirementPolicies
autonomousSystemNumber
azureResourceId
clientAppUsed
clientCredentialType
conditionalAccessAudiences
conditionalAccessStatus
correlationId
createdDateTime
crossTenantAccessType
deviceDetail
federatedCredentialId
flaggedForReview
globalSecureAccessIpAddress
homeTenantId
homeTenantName
id
incomingTokenType
ipAddress
ipAddressFromResourceProvider
isInteractive
isTenantRestricted
isThroughGlobalSecureAccess
location
managedServiceIdentity
networkLocationDetails
originalRequestId
originalTransferMethod
privateLinkDetails
processingTimeInMilliseconds
resourceDisplayName
resourceId
resourceOwnerTenantId
resourceServicePrincipalId
resourceTenantId
riskDetail
riskEventTypes_v2
riskLevelAggregated
riskLevelDuringSignIn
riskState
servicePrincipalCredentialKeyId
servicePrincipalCredentialThumbprint
servicePrincipalId
servicePrincipalName
sessionLifetimePolicies
signInEventTypes
sessionId
signInIdentifier
signInIdentifierType
signInTokenProtectionStatus
status
tokenIssuerName
tokenIssuerType
tokenProtectionStatusDetails
uniqueTokenIdentifier
userAgent
userDisplayName
userId
userPrincipalName
userType
mfaDetail            (marked deprecated)
```

- **Which version has what (CONFIRMED):** `sessionId`, `uniqueTokenIdentifier`, `authenticationRequirement`,
  `authenticationDetails`, `signInEventTypes`, `userAgent` and `mfaDetail` are **beta only**. They are absent from
  v1.0 (both the Markdown source and the rendered Learn page were checked). An export made through the v1.0 API
  therefore cannot be joined to the UAL by session or token.

#### 2b-4 Nested types

- **Status:** CONFIRMED
- **Sources:** S19c, S19b (retrieved 2026-11-17)

```text
deviceDetail:    browser, deviceId, displayName, isCompliant, isManaged, operatingSystem, trustType
signInLocation:  city, countryOrRegion, geoCoordinates, state
geoCoordinates:  altitude, latitude, longitude
signInStatus:    additionalDetails, errorCode, failureReason
mfaDetail:       authDetail, authMethod          (beta, deprecated)
authenticationDetail (beta): see 2a-3
```

#### 2b-5 Value notes

- **Status:** CONFIRMED unless marked
- **Sources:** S19a, S19b, S16, S26, S27 (retrieved 2026-11-17)
  - `createdDateTime` is UTC ISO 8601 with `Z` (Microsoft's example is midnight 2014-01-01 as `2014-01-01T00:00:00Z`).
  - `userPrincipalName` is always lower case. For guests the sign-in log stores the real address, not the `#EXT#` form.
  - `clientAppUsed`: v1.0 gives examples `Browser`, `modern clients`, `Exchange ActiveSync`, `IMAP`, `MAPI`, `SMTP`,
    `POP`, `other clients`. Beta gives `Browser`, `Exchange ActiveSync`, `Modern clients`, `IMAP`, `MAPI`, `SMTP`,
    `POP`. The full exact value set in data (for example `Mobile Apps and Desktop clients`, `Authenticated SMTP`,
    `IMAP4`, `POP3`, `Other clients`) is UNCONFIRMED; compare case-insensitively. See 2a-2 for the UI names.
  - `conditionalAccessStatus`: `success`, `failure`, `notApplied`, `unknownFutureValue`.
  - `riskLevelDuringSignIn` / `riskLevelAggregated`: `none`, `low`, `medium`, `high`, `hidden`, `unknownFutureValue`
    (`hidden` without a P2 licence).
  - `signInEventTypes`: `interactiveUser`, `nonInteractiveUser`, `servicePrincipal`, `managedIdentity`,
    `unknownFutureValue`. The beta list API returns only interactive sign-ins unless filtered.
  - `authenticationRequirement`: for example `singleFactorAuthentication`, `multiFactorAuthentication`. A failed
    primary authentication shows single-factor (S16).
  - `uniqueTokenIdentifier`: a base64-encoded request identifier (S19b, S26).
  - `status.errorCode`: the Graph table only says it is the error code for failures. "0 means success" is stated
    for Azure Monitor `ResultType` (S26) and UAL `ErrorCode` (S1), not on the Graph page (PARTIAL).
  - `correlationId`: supplied by the client and not guaranteed accurate (S16). Its presence in several logs does
    not mean they can be joined on it (S27).

### 2c. Microsoft Entra audit logs (Graph `directoryAudit`)

- **Status:** CONFIRMED
- **Sources:** S20, S27, S23, S15 (retrieved 2026-11-17)

```text
directoryAudit:         activityDateTime, activityDisplayName, additionalDetails, category, correlationId, id,
                        initiatedBy, loggedByService, operationType, result, resultReason, targetResources
auditActivityInitiator: app, user
userIdentity:           displayName, id, ipAddress, userPrincipalName
appIdentity:            appId, displayName, servicePrincipalId, servicePrincipalName
targetResource:         displayName, groupType, id, modifiedProperties, type, userPrincipalName
modifiedProperty:       displayName, newValue, oldValue
```

- **Paraphrase:**
  - `activityDateTime` is UTC; S23's sample has seven fractional digits and `Z`.
  - `result` is `success`, `failure`, `timeout` or `unknownFutureValue`.
  - `operationType` includes `Add`, `Assign`, `Update`, `Unassign`, `Delete` (not exhaustive).
  - `category` examples: `UserManagement`, `GroupManagement`, `ApplicationManagement`, `RoleManagement`.
  - `loggedByService` examples include `Core Directory`.
  - `initiatedBy.user.ipAddress` is the OAuth client's IP (the TCP peer), which is often not the end user's (S15, S27).
  - S23's sample also carries `userType`, `homeTenantId`, `homeTenantName` under `initiatedBy.user`, which the
    v1.0 `userIdentity` table does not list. Accept extra keys.
- **Out of scope / UNCONFIRMED:** column headers of the Entra audit-log CSV download.

---

## 3. Linking UAL activity back to sign-ins

- **Status:** CONFIRMED (mapping); caveats noted
- **Sources:** S25 (primary), S1, S26, S27 (retrieved 2026-11-17)
- **Paraphrase:** Entra puts linkable identifiers in every access token and surfaces them in the logs. The session
  ID (`sid`) ties together every token and cookie issued from one interactive sign-in. The unique token identifier
  (`uti`) identifies one token or request. Microsoft's guidance is to take the Session ID or UTI from the sign-in
  log and search Purview audit exports by `AADSessionId` (whole session) or `UniqueTokenId` (one token).

```text
Claim   Entra sign-in log         Exchange Online audit (UAL)                          SharePoint Online audit (UAL)     Teams audit (UAL)        Graph activity logs
oid     User ID                   TokenObjectId                                        UserObjectId                      UserKey                  UserId
tid     Resource Tenant ID        TokenTenantId                                        OrganizationId                    OrganizationId           TenantId
sid     Session ID                SessionID / AADSessionId within AppAccessContext     AADSessionId (AppAccessContext)   AADSessionId             SessionId
deviceid Device ID                DeviceId (registered/joined devices only)            DeviceId                          DeviceId                 DeviceId
uti     Unique Token Identifier   UniqueTokenId within AppAccessContext                UniqueTokenId (AppAccessContext)  UniqueTokenId            SignInActivityId
iat     Date                      IssuedAtTime within AppAccessContext                 IssuedAtTime (AppAccessContext)   IssuedAtTime             TokenIssuedAt
```

Join keys for TenantTrace:

| UAL side | Sign-in side | Status |
|---|---|---|
| `AppAccessContext.AADSessionId` | Graph beta `sessionId`, CSV "Session ID", Azure Monitor `SessionId` | CONFIRMED (S25, S1, S19b, S26) |
| `AppAccessContext.UniqueTokenId` | Graph beta `uniqueTokenIdentifier`, CSV "Unique token identifier", Azure Monitor `UniqueTokenIdentifier` | CONFIRMED (S25). Case-sensitive per S1 and S25: never case-fold. |
| `TokenObjectId` (Exchange) | `userId` / "User ID" | CONFIRMED (S25) |
| `DeviceId` | `deviceDetail.deviceId` / "Device ID" | CONFIRMED (S25), registered or joined devices only |
| Exchange mailbox `SessionId` | `sessionId` | PARTIAL. S25 lists `SessionID` next to `AADSessionId` for Exchange, but S1 only calls it a session identifier; equality for every client is not stated. |
| STS logon `DeviceProperties` entry `SessionId` | `sessionId` | UNCONFIRMED. S1 mentions SessionId only in prose; equality is not documented. |
| `AppAccessContext.CorrelationId` / sign-in `correlationId` | | Not a join key. S27 says a shared correlationId does not mean logs can be joined; S16 says it is client-supplied. |

Caveats (CONFIRMED, S25):
- Identifiers are missing on some aggregated Exchange entries and on entries from background processes. Expect
  gaps in MailItemsAccessed and system-generated records.
- In Entra audit logs the session link (DUSI) exists only when the event carries an authenticated user session.
- S25 also shows a Log Analytics join of Graph activity logs to sign-in logs on `SignInActivityId` = `UniqueTokenIdentifier`.
- Graph v1.0 `signIn` has neither `sessionId` nor `uniqueTokenIdentifier` (2b-3). Use the admin-center download,
  Graph beta, or Azure Monitor for linking.
- Aside: S1's OWA Auth schema has its own `UniqueTokenIdentifier` field (with `ResourceURL`). It is a separate record
  type, not part of AppAccessContext.

---

## Parser implications (derived from the above, not Microsoft statements)

1. Match CSV headers case-insensitively with whitespace normalised. Detect the UAL CSV variant (four-column vs
   newer) and the Entra file type from the header set, never from the file name.
2. Treat `AuditData` as the source of truth. Use `AuditData.CreationTime`; treat timestamps without an offset as UTC;
   accept `Z` and up to seven fractional digits.
3. Accept `RecordType` as an integer or a name. Compare `Operation` case-insensitively; keep the original string,
   including any trailing period, for display.
4. `ResultStatus` comparisons should be case-insensitive and accept `True`/`False`. For STS logons, decide
   success from `ErrorCode`/`ErrorNumber`/`LogonError`, not `ResultStatus`.
5. Deduplicate UAL rows on `AuditData.Id`. Exports and `ReturnLargeSet` pages can repeat records and are unsorted.
6. Flag possible truncation when a file hits a documented ceiling: 50,000 or 1,000,000 (Purview export);
   5,000, 10,000 or 50,000 (Search-UnifiedAuditLog); 100,000 (Entra sign-ins); 250,000 (Entra audit).
7. Accept spelling variants seen in Microsoft's own docs: `IntraSystemsId`/`IntraSystemId`,
   `ErrorCode`/`ErrorNumber`, `web`/`Web`.
8. `ModifiedProperties` has two shapes: a list of strings in single-item mailbox records, and Name/NewValue/OldValue
   objects in admin, SharePoint and Entra records. `newValue`/`NewValue` may itself be a JSON-encoded string.
9. Do not assume a separator for multi-valued `Parameters` values.
10. MailItemsAccessed: treat `Sync` as whole-folder exposure; count `Bind` items via `FolderItems[].InternetMessageId`
    and `OperationCount`; surface `IsThrottled` if present.
11. Never case-fold UTI values. Session IDs are GUID strings and can be compared case-insensitively.
12. The Entra CSV is lossy (no nested arrays, possible PII redaction, duplicates per Request ID); prefer the JSON
    download when both exist. A Purview export by a restricted (admin-unit-scoped) admin is incomplete.

## Open questions

1. Exact header row, order and encoding (BOM or not) of the current Purview Audit search-job CSV. Are
   `RecordId`, `RecordType`, `Operation`, `UserId`, `AssociatedAdminUnits`, `AssociatedAdminUnitsNames` top-level
   columns, and what is the `CreationDate` text format? (1a-2, 1a-3)
2. Does `RecordId` (Purview CSV) and `Identity` (Search-UnifiedAuditLog) equal `AuditData.Id`? (1a-2, 1b-1)
3. Full `Export-Csv` header for Search-UnifiedAuditLog (`RunspaceId`, `IsValid`, `ObjectState`,
   `AuditSearchRequestMetadata`?), its order, the time zone of `CreationDate`, and whether `RecordType` comes out as
   a name or a number. (1b-1)
4. JSON shape of `AppAccessContext` (object or array) and the format of `IssuedAtTime`. (1c-4)
5. `UpdateInboxRules` rule fields inside `OperationProperties`, and its RecordType. (1d-4)
6. Serialization of `Parameters[].Value` for multi-valued parameters, switches and forwarding addresses. (1d-3, 1d-5)
7. STS logon field spellings in real records: `ErrorNumber` vs `ErrorCode`, `IntraSystemId` vs `IntraSystemsId`,
   `ExtendedProperties` keys (`UserAgent`, `RequestType`, `ResultStatusDetail`, ...), `DeviceProperties` Name
   strings. Also the RecordType of `UserLoggedIn`. (1g-1, 1g-2)
8. UAL operation strings (with trailing period) for consent, delegated grants, app-role assignment
   (`Add app role assignment grant to user.`), security-info and device activities. (1g-3)
9. UAL `ModifiedProperties` Names and the value format of `ConsentAction.Permissions` for scope extraction. (1g-4)
10. Entra sign-in CSV headers for all six download variants (incl. the authentication-details files), their casing
    and order, the `Date (UTC)` and `Location` formats, default file names, and whether the non-interactive
    download is aggregated like the UI. (2a-2 to 2a-5)
11. Layout of the Entra JSON download (Graph beta-like or not). (2b-1)
12. The full exact set of `clientAppUsed` strings in exported data. (2b-5)
13. Whether MailItemsAccessed throttling and `IsThrottled` still apply, since the current Purview article dropped them. (1e-2)
14. Whether the Exchange mailbox `SessionId` and the STS `DeviceProperties` `SessionId` always equal the Entra sign-in
    `sessionId`. (Section 3)
15. RecordType (2 vs 3) for `SoftDelete`, `HardDelete`, `MoveToDeletedItems`, `Move`, and the RecordType of the
    permission cmdlets. (1d-6, 1e-3)
16. The real value set of `TargetUserOrGroupType`. (1f-3)
17. The history of the Purview Premium export cap (100,000 vs 1,000,000), which affects how old exports are judged. (1a-4)

Closing these needs sanitised sample exports from a test tenant (one per format), kept as parser fixtures.
