# Log-source retention, licensing and default state (Microsoft 365 / Entra)

Retrieved: **2026-11-17**. Purpose: reference table for TenantTrace evidence-gap analysis.

**Status rules used in this file**

- **CONFIRMED**: stated on a learn.microsoft.com page fetched on the retrieval date (page dates listed below).
- **UNCONFIRMED**: not found on learn.microsoft.com on that date. This includes facts that appear only on Microsoft Tech Community blogs, Q&A threads, collector documentation or memory. These are labelled with where they *were* seen, if anywhere.
- Quotes are kept under 15 words; everything else is paraphrase. Microsoft pages change often, so re-check them before release.

## Sources consulted

| Key | URL | ms.date | updated_at |
|---|---|---|---|
| P1 | https://learn.microsoft.com/en-us/purview/audit-solutions-overview | 2026-05-18 | 2026-07-08 |
| P2 | https://learn.microsoft.com/en-us/purview/audit-log-retention-policies | 2026-06-19 | 2026-06-24 |
| P3 | https://learn.microsoft.com/en-us/purview/audit-mailboxes | 2026-06-19 | 2026-08-22 |
| P4 | https://learn.microsoft.com/en-us/purview/audit-log-enable-disable | 2026-06-19 | 2026-06-24 |
| P5 | https://learn.microsoft.com/en-us/purview/audit-log-investigate-accounts | 2026-06-19 | 2026-06-24 |
| P6 | https://learn.microsoft.com/en-us/purview/audit-search | 2026-06-19 | 2026-07-14 |
| P7 | https://learn.microsoft.com/en-us/purview/audit-get-started | 2026-02-18 | 2026-09-08 |
| P8 | https://learn.microsoft.com/en-us/purview/audit-log-export-records | 2026-06-19 | 2026-06-24 |
| P9 | https://learn.microsoft.com/en-us/purview/audit-log-sharing | 2026-06-19 | 2026-06-25 |
| P10 | https://learn.microsoft.com/en-us/purview/audit-log-activities | 2026-11-03 | 2026-11-13 |
| P11 | https://learn.microsoft.com/en-us/powershell/module/exchange/search-unifiedauditlog (canonical: .../module/exchangepowershell/search-unifiedauditlog) | 2017-09-25 | 2026-06-01 |
| P12 | https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema | 2026-10-01 | 2026-10-07 |
| E1 | https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-reports-data-retention | 2026-01-06 | 2026-03-25 |
| E2 | https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins | 2025-11-07 | 2026-02-26 |
| E3 | https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-noninteractive-sign-ins | 2026-02-09 | 2026-02-26 |
| E4 | https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-service-principal-sign-ins | 2025-03-17 | 2026-02-26 |
| E5 | https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-audit-logs | 2026-06-05 | 2026-06-16 |
| E6 | https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-download-logs | 2024-11-08 | 2026-02-26 |
| E7 | https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-access-activity-logs | 2026-06-24 | 2026-06-30 |
| E8 | https://learn.microsoft.com/en-us/entra/fundamentals/licensing | 2026-06-18 | 2026-07-28 |
| E9 | https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-beta | 2025-06-18 | 2025-07-23 |
| E10 | https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0 | 2024-07-30 | 2025-11-04 |
| S1 | https://learn.microsoft.com/en-us/troubleshoot/microsoft-365/purview/audit-logs/mailbox-audit-logs (support article) | 2025-05-05 | 2025-10-08 |
| T1 (not Learn) | https://techcommunity.microsoft.com/blog/microsoft-security-blog/increased-security-visibility-through-new-standard-logs-in-microsoft-purview-aud/4144454 | published 2024-05-20 | updated 2024-06-12 |
| T2 (not Learn) | https://techcommunity.microsoft.com/blog/microsoft-security-blog/exchange-online-mailbox-auditing-enabled-by-default/361324 | published 2019-03-06 | updated 2021-05-11 |

Note: `https://learn.microsoft.com/en-us/purview/audit-premium` now returns the same content as P1. There is no longer a separate Audit (Premium) article listing "intelligent insights" events by name.

---

## 1. Quick reference

| Log source | What it records | Licence | Default retention | On by default | Status |
|---|---|---|---|---|---|
| Unified audit log, Audit (Standard) | User and admin operations across Microsoft 365 services | "Appropriate subscription". Learn defers the SKU list to aka.ms/M365EnterprisePlans. | **180 days** for records created on/after **2023-10-17**. **90 days** for older records. | Yes for enterprise orgs. **No** for Business Basic, Business Standard, Business Premium, or unmanaged tenants on free enterprise trials. | CONFIRMED (P1, P2, P4, P6, P7). SKU list UNCONFIRMED. |
| Audit (Premium) | Standard features plus retention policies, intelligent insights and higher API bandwidth | Office 365 or Microsoft 365 E5, Microsoft Purview Suite (formerly M365 E5 Compliance), or the E5 eDiscovery and Audit add-on. The Advanced Auditing service plan must be on for each user. | **1 year** for records whose Workload is AzureActiveDirectory, Exchange, OneDrive or SharePoint. 180 days for everything else. Up to **10 years** with the per-user add-on. | The default 1-year policy applies automatically to licensed users. | CONFIRMED (P1, P2, P6, P7) |
| MailItemsAccessed | Mail access by protocols and clients (sync and bind) | Learn says it is part of Audit (Standard). It is on by default for Office 365 or Microsoft 365 **E3/E5** users. | Follows the user's audit retention | Yes, for Admin, Delegate and Owner logon types | CONFIRMED (P3, P5). The date it moved from Premium to Standard is UNCONFIRMED. |
| Send | Sending, replying to or forwarding a message | The Learn mailbox table gives no licence condition. T1 lists it as a Standard log in public preview in 2024. | Follows the user's audit retention | Yes for Admin and Owner. Not available for Delegate. | Default state CONFIRMED (P3). Licence history UNCONFIRMED. |
| SearchQueryInitiatedExchange | Searches in an Exchange Online mailbox (Outlook clients) | No Premium caveat on Learn. T1 lists it as a Standard log in public preview. | Follows the user's audit retention | **No**. It must be enabled per user. | Enablement CONFIRMED (P3, P7). Licence UNCONFIRMED. |
| SearchQueryInitiatedSharePoint | Searches in SharePoint | Same as above | Follows the user's audit retention | Yes, according to P7 | CONFIRMED (P7) |
| Exchange mailbox auditing | Mailbox actions by owner, delegate and admin | All organisations | Managed by Purview audit retention. `AuditLogAgeLimit` no longer applies. | Yes, for user, shared and Microsoft 365 Group mailboxes. Not supported for public folder or resource mailboxes. | CONFIRMED (P3). Start date UNCONFIRMED (see §6). |
| SharePoint/OneDrive file and sharing events | File operations, sharing, links, access requests, sync | Audit (Standard) | 180 days. 1 year under Premium (Workload SharePoint/OneDrive). | Yes, when UAL ingestion is on | CONFIRMED (P2, P9, P10) |
| Entra sign-in logs | Interactive, non-interactive, service principal and managed identity sign-ins | Free: yes in the admin centre. Programmatic Graph access needs P1/P2. | **Free 7 days; P1/P2 30 days** | Yes. On Free, collection starts the first time the portal or reporting API is used. | CONFIRMED (E1, E6, E7, E8). Per-type availability on Free UNCONFIRMED. |
| Entra audit logs | Directory changes (users, groups, apps, licences and more) | Free: yes. Programmatic Graph access needs P1/P2. | **Free 7 days; P1/P2 30 days** | Yes | CONFIRMED (E1, E5, E7, E8) |

### Limits and timing

| Item | Value | Source | Status |
|---|---|---|---|
| Purview audit search export | 50,000 rows (Standard); 1,000,000 rows (Premium) per search. Results above the limit are silently incomplete. | P6, P8 | CONFIRMED |
| Purview search date range | Maximum 180 days; default is the last 7 days | P6 | CONFIRMED |
| Purview concurrent search jobs | Up to 10 per user, with at most 1 unfiltered | P6 | CONFIRMED |
| Purview completed-job retention | 30 days | P6 | CONFIRMED |
| Purview search run time | Broad searches in large tenants can take up to 48 hours | P6 | CONFIRMED |
| Purview result count | Shown as an approximate count above 100,000 results | P6 | CONFIRMED |
| `Search-UnifiedAuditLog` default | 100 records | P11 | CONFIRMED |
| `-ResultSize` maximum | 5,000 | P11 | CONFIRMED |
| `-SessionCommand ReturnLargeSet` | Pages up to **50,000** results per session ID; output is **unsorted** | P11 | CONFIRMED |
| `-SessionCommand ReturnNextPreviewPage` | Sorted by date; maximum 5,000 records | P11 | CONFIRMED |
| Mixing both commands on one SessionId | Output capped at 10,000 | P11 | CONFIRMED |
| `-HighCompleteness` | Preview, not in all orgs. More complete but slower; without it results "might have missing search results". | P11 | CONFIRMED |
| Entra admin-centre download | 100,000 sign-in or provisioning records per file; 250,000 audit records per file; CSV or JSON; UTC timestamps | E6 | CONFIRMED |
| Graph `GET /auditLogs/signIns` | Default and maximum page size 1,000 | E9, E10 | CONFIRMED |
| Office 365 Management Activity API | Baseline 2,000 requests per minute, scaled by seats and licence. E5/A5/G5 get about twice the bandwidth. | P1 | CONFIRMED |
| Audit log retention policies | Up to 50 per organisation | P2 | CONFIRMED |
| UAL record availability (latency) | Core services (Exchange, SharePoint, OneDrive, Teams): typically **60–90 minutes**; other services can take longer; no guarantee | P6 | CONFIRMED |
| Turning auditing on | Takes up to 60 minutes; events can take several hours to become searchable | P4 | CONFIRMED |
| Audit (Premium) insights after enabling the service plan | Begin within 24 hours | P7 | CONFIRMED |
| Entra data after upgrading from Free | Up to 3 days to appear if there was no prior data | E1 | CONFIRMED |
| Entra sign-in and audit log latency | Not stated on the fetched pages | — | UNCONFIRMED |

---

## 2. Unified audit log: Audit (Standard)

- **Records:** user and admin activity across Microsoft services. It is searchable in the Purview portal, with `Search-UnifiedAuditLog` (Exchange Online PowerShell), with the Audit Search Graph API, and through the Office 365 Management Activity API. (P1) CONFIRMED.
- **Licence:** "Enabled by default for all organizations with the appropriate subscription" (P1). Learn links to aka.ms/M365EnterprisePlans for the SKU list instead of listing SKUs itself. That list was not checked, so the **SKU list is UNCONFIRMED**.
- **Retention:** 180 days. Logs created **before 2023-10-17** keep 90 days; logs created **on or after 2023-10-17** get 180 days. This wording appears on P1, P2, P6 and P7. CONFIRMED.
- **Retention is fixed when a record is ingested.** Changing a licence or policy changes expiry only for data that arrives after the change. Records already stored are not affected. (P1, P2) CONFIRMED.
- **On by default:**
  - P4 says audit logging is on by default for Microsoft 365 organisations, but should be verified for new ones.
  - P4 also says auditing is **not** on by default for SMB licences (Microsoft 365 Business Basic, Business Standard, Business Premium) or for unmanaged tenants on free enterprise trials. In those tenants an admin must turn it on.
  - CONFIRMED.
- **Change history:**
  - 90 → 180 days for records from 2023-10-17 onward. CONFIRMED.
  - Classic Search retired on 2023-11-30 (P1). CONFIRMED.

## 3. Audit (Premium): 1-year default and 10-year add-on

- **Default policy:** keeps every record whose `Workload` is AzureActiveDirectory, Exchange, OneDrive or SharePoint for one year. The policy cannot be changed or viewed in the dashboard, and `Get-UnifiedAuditLogRetentionPolicy` does not return it. (P2) CONFIRMED.
- **Who it covers:** only activity by users with Office 365 or Microsoft 365 E5, Microsoft Purview Suite (formerly Microsoft 365 E5 Compliance), or the E5 eDiscovery and Audit add-on. Activity by non-E5 users and guests is kept for 180 days. (P2, P6) CONFIRMED.
- **Service plan:** the "Microsoft 365 Advanced Auditing" app must be enabled for each user. Logging of Premium insights then starts within 24 hours. (P7) CONFIRMED.
- **10-year retention:**
  - Needs a per-user **10-Year Audit Log Retention add-on** on top of E5, plus a matching policy.
  - The policy is **not retroactive**.
  - Policy durations offered: 7 days, 30 days, 6 months, 9 months, 1 year, 3, 5, 7 years, and 10 years with the add-on. The 7- and 30-day options need an M365 E5 subscription; the 3/5/7-year options need the add-on.
  - (P1, P2) CONFIRMED.
- **Non-user entities:** records created by service principals, system events and application activity are kept for a fixed **one year**. This cannot be configured, and custom policies do not apply. (P1, footnote under the 10-year row.) CONFIRMED as written. **Whether this also applies to tenants without Premium is not stated (UNCONFIRMED).**
- **Custom policies outrank the default.** For example, a short Exchange policy shortens Exchange retention. (P2) CONFIRMED.
- **Other Premium features:**
  - A `SensitivityLabel` property on MailItemsAccessed.
  - `AppAccessContext` and related properties on Teams events.
  - Tenant-level, roughly double bandwidth on the Management Activity API.
  - (P1) CONFIRMED.

## 4. MailItemsAccessed

- **Records:** access to mail data over POP, IMAP, MAPI, EWS, Exchange ActiveSync and REST. (P5) CONFIRMED.
  - **Sync:** recorded only for Outlook desktop on Windows or Mac. One record per synced folder, and every item in that folder should be treated as accessed. Access after a sync, offline, is not audited.
  - **Bind:** individual message access, identified by `InternetMessageId`. Binds within a **2-minute** window are combined into one record (`OperationCount`, `Folders`).
  - **De-duplication:** repeated binds within one hour are filtered out, and syncs are filtered at one-hour intervals. A new record is still written if any of these differ: `ClientIPAddress`, `ClientInfoString`, `ParentFolder`, `Logon_type`, `MailAccessType`, `MailboxUPN`, `User`, `SessionId`.
- **Licence:** "part of Audit (Standard)". It is on by default for users with **Office 365 E3/E5 or Microsoft 365 E3/E5**. (P5) CONFIRMED (current text).
- **On by default** for the Admin, Delegate and Owner logon types (P3 table). CONFIRMED.
- **Record type:** `ExchangeItemAggregated` (value **50**), described as MailItemsAccessed events. (P12) CONFIRMED.
- **Change history:**
  - Earlier this event needed Audit (Premium). T1 (Tech Community, 2024-05-20) lists `mailitemsaccessed`, `send`, `searchqueryinitiatedexchange` and `searchqueryinitiatedsharepoint` among 19 logs in **public preview** for Audit (Standard). It gives **no GA date**.
  - The current Learn page treats it as Standard.
  - **The effective date of the change: UNCONFIRMED on Learn.**
- **Throttling:** older documentation described throttling of more than 1,000 records in 24 hours, with an `IsThrottled` flag. **P5 no longer mentions throttling. Current status UNCONFIRMED.**
- **Caveat for Standard users:** T1 says that for Standard-licensed users, `Set-Mailbox -AuditEnabled $true` must be run so the events reach the UAL. **This is not on Learn (UNCONFIRMED).** P6 does confirm that mailbox audit events for some users may be missing from audit searches even with default-on auditing.

## 5. Send, SearchQueryInitiatedExchange, SearchQueryInitiatedSharePoint

- **Send:** covers sending, replying to and forwarding messages. It is logged by default for **Admin** and **Owner**; the **Delegate** logon type cannot log it, because delegate sends appear as `SendAs` or `SendOnBehalf`, which are on by default for Admin and Delegate. (P3) CONFIRMED. Licence history: see §4 (UNCONFIRMED on Learn).
- **SearchQueryInitiatedExchange:**
  - Must be enabled explicitly, per user: `Set-Mailbox <user> -AuditOwner @{Add="SearchQueryInitiated"}`. (P7) CONFIRMED.
  - The P3 table shows `SearchQueryInitiated` as available only for Owner and not on by default. CONFIRMED.
  - In multi-geo tenants the command must run in the forest that holds the mailbox. (P7) CONFIRMED.
  - The operation name in the activity list is `SearchQueryInitiated`. (P10) CONFIRMED.
- **SearchQueryInitiatedSharePoint:**
  - P7 says it is enabled by default. The add/remove switch is `Set-Mailbox <user> -AuditOwner @{Add="SharepointSearchQueryInitiated"}`. CONFIRMED.
  - The activity-list operation name `SharepointSearchQueryInitiated` was reported by the fetch tool. **Exact table placement UNCONFIRMED.**
- **Licence:** P7 presents step 3 (these search events) separately from step 4 (Premium/E5 setup) and gives no E5 condition for it. T1 lists both as Standard preview logs. **An explicit licence statement on Learn is UNCONFIRMED.**

## 6. Exchange mailbox auditing on by default

- **State:** "turned on by default in all organizations" (P3). CONFIRMED.
  - Check with `Get-OrganizationConfig | Format-List AuditDisabled`; `False` means on.
  - When it is on, `Get-Mailbox` always shows `AuditEnabled` as True, and setting a mailbox's `AuditEnabled` to False is ignored.
- **Since when:**
  - The current Learn pages give **no start date**.
  - T2 (Tech Community, 2019-03-06) says it "has now been enabled by default and rolled out worldwide", with the UAL part still rolling out.
  - **The commonly cited "January 2019" start is UNCONFIRMED** on the pages fetched.
- **Mailbox types (P3), CONFIRMED:**

  | Mailbox type | Auditing supported | On by default |
  |---|---|---|
  | User | Yes | Yes |
  | Shared | Yes | Yes |
  | Microsoft 365 Group | Yes | Yes |
  | Public folder | No | No |
  | Resource | No | No |

  - The DiscoverySearch mailbox is not mentioned (UNCONFIRMED).
  - **Multi-geo:** cross-geo mailbox auditing is not supported. A user acting on a shared mailbox in another geo is not logged in that mailbox's audit log. CONFIRMED.
- **Logon types (P3), CONFIRMED:**
  - **Owner:** the mailbox's own account.
  - **Delegate:** a user with SendAs, SendOnBehalf or FullAccess. An admin with FullAccess also counts as a delegate.
  - **Admin:** eDiscovery searches, MAPI Editor, or access through ApplicationImpersonation.
- **Actions logged by default on user and shared mailboxes (P3), CONFIRMED:**

  | Logon type | Default actions |
  |---|---|
  | Admin | ApplyRecord, AttachmentAccess, Create, HardDelete, MailItemsAccessed, MoveToDeletedItems, Send, SendAs, SendOnBehalf, SoftDelete, Update, UpdateCalendarDelegation, UpdateFolderPermissions, UpdateInboxRules |
  | Delegate | ApplyRecord, AttachmentAccess, Create, HardDelete, MailItemsAccessed, MoveToDeletedItems, SendAs, SendOnBehalf, SoftDelete, Update, UpdateFolderPermissions, UpdateInboxRules |
  | Owner | ApplyRecord, AttachmentAccess, Create, HardDelete, MailItemsAccessed, MoveToDeletedItems, Send, SoftDelete, Update, UpdateCalendarDelegation, UpdateFolderPermissions, UpdateInboxRules |

  - Available but **not** default:
    - Copy: Admin.
    - FolderBind: Admin and Delegate. Delegate FolderBind is consolidated to one record per folder per 24 hours.
    - MailboxLogin: Owner.
    - MessageBind: Admin, and only for users *without* E5/A5/G5.
    - Move: all logon types.
    - RecordDelete: all logon types.
    - SearchQueryInitiated: Owner.
  - `AttachmentAccess` records attachment access through Microsoft Graph. It is always on and cannot be configured.
- **Microsoft 365 Group mailboxes (P3), CONFIRMED.** The defaults are fixed and cannot be changed:
  - Create: Admin and Delegate.
  - HardDelete: all logon types.
  - MoveToDeletedItems: all logon types.
  - SendAs: Admin and Delegate.
  - SendOnBehalf: Admin and Delegate.
  - SoftDelete: all logon types.
  - Update: all logon types.
- **Customisation (P3), CONFIRMED:**
  - `DefaultAuditSet` shows which logon types still use Microsoft-managed defaults. `Admin, Delegate, Owner` means none have been customised.
  - Once a logon type's action list is customised, **new default actions are no longer added automatically** for it.
  - A list customised before default-on auditing arrived was kept.
- **Bypass (P3), CONFIRMED:**
  - `Set-MailboxAuditBypassAssociation -Identity <user> -AuditByPassEnabled $true` stops logging of **all** mailbox actions by that user: as owner, as delegate on other mailboxes, and as admin.
  - Check with `Get-MailboxAuditBypassAssociation -Identity <user> | Format-List AuditByPassEnabled`.
- **Organisation-wide off switch (P3), CONFIRMED:**
  - `Set-OrganizationConfig -AuditDisabled $true` stops all mailbox auditing and ignores bypass settings.
  - Existing records are kept until they expire.
- **Retention:** `AuditLogAgeLimit` no longer applies; retention is managed through Purview (P3). CONFIRMED.
  - The older support article S1 still says mailbox audit entries are kept in the mailbox for 90 days, in the context of `Search-MailboxAuditLog`. Treat that as legacy.

## 7. UAL ingestion on by default, and how to check

- See §2 for the default state and the SMB/trial exception (P4). CONFIRMED.
- **Check:** run `Get-AdminAuditLogConfig | Format-List UnifiedAuditLogIngestionEnabled` in **Exchange Online PowerShell**. `True` means on. CONFIRMED (P4, P6).
  - In Security & Compliance PowerShell this property **is always `False`**, even when auditing is on.
- **Turn on:** `Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true`, or the Purview banner. Takes up to 60 minutes. (P4) CONFIRMED.
- **Effect of turning it off:** the Management Activity API and Microsoft Sentinel cannot read audit data, and Purview search and `Search-UnifiedAuditLog` return nothing. (P4) CONFIRMED.
- **Changes are themselves audited:** `Search-UnifiedAuditLog -Operations Set-AdminAuditLogConfig` finds them. The record shows the admin, the time and the IP address. (P4) CONFIRMED.

## 8. SharePoint and OneDrive file and sharing events

- **Record types (P12), CONFIRMED:**

  | Name | Value |
  |---|---|
  | SharePoint | 4 |
  | SharePointFileOperation | 6 |
  | SharePointSharingOperation | 14 |
  | SharePointSearch | 102 (searching an organisation's SharePoint home site) |

- **File and page operations (P10), CONFIRMED.** Includes:
  - Access and change: `FileAccessed`, `FileAccessedExtended`, `FileDownloaded`, `FileUploaded`, `FileModified`, `FileModifiedExtended`, `FilePreviewed`.
  - Copy, move and delete: `FileCopied`, `FileMoved`, `FileRenamed`, `FileDeleted`, `FileRecycled`, `FileRestored`, `FileDeletedFirstStageRecycleBin`, `FileDeletedSecondStageRecycleBin`.
  - Check-in and malware: `FileCheckedIn`, `FileCheckedOut`, `FileMalwareDetected`.
  - Pages and search: `PageViewed`, `PageViewedExtended`, `SearchQueryPerformed`.
  - The `*Extended` events cover continuous access by the same person for up to three hours.
  - The fetch tool also reported that `FileAccessed`/`FileModified` are not repeated for the same user and file within five minutes. **That wording was not captured verbatim (UNCONFIRMED wording).**
- **Sync operations (P10), CONFIRMED:**
  - `FileSyncDownloadedFull` and `FileSyncUploadedFull` come from OneDrive.exe.
  - `FileSyncDownloadedPartial` and `FileSyncUploadedPartial` are deprecated along with Groove.exe.
- **Sharing and access-request operations (P10), CONFIRMED:**
  - Sharing: `SharingSet`, `SharingRevoked`, `SharingInvitationCreated`, `SharingInvitationAccepted`, `SharingInvitationRevoked`, `SharingInvitationUpdated`, `SharingInvitationBlocked`.
  - Anyone links: `AnonymousLinkCreated`, `AnonymousLinkUpdated`, `AnonymousLinkRemoved`, `AnonymousLinkUsed`.
  - Company-wide links: `CompanyLinkCreated`, `CompanyLinkRemoved`, `CompanyLinkUsed`.
  - Specific-people links: `SecureLinkCreated`, `SecureLinkDeleted`, `SecureLinkUsed`, `AddedToSecureLink`, `RemovedFromSecureLink`.
  - Access requests: `AccessRequestCreated`, `AccessRequestAccepted`, `AccessRequestDenied`, `AccessRequestUpdated`.
  - Permissions: `PermissionLevelAdded`.
- **Sharing schema (P9), CONFIRMED:**
  - Adds `TargetUserOrGroupType` (Member, Guest, SharePointGroup, SecurityGroup, Partner) and `TargetUserOrGroupName`.
  - **Sharing with a user already in the directory** logs `AddedToGroup` and `SharingSet`.
  - **Sharing with a user not in the directory** logs one of: `AnonymousLinkCreated`, `SecureLinkCreated`, `AddedToSecureLink`, or `SharingInvitationCreated` (sites only). Acceptance logs `SharingInvitationAccepted`. Using an Anyone link logs `AnonymousLinkUsed`. An external user opening a specific-people link logs `FileAccessed`.
- **Licence, retention and default:**
  - Part of Audit (Standard); Learn names no Premium requirement for these operations.
  - Kept 180 days, or 1 year for E5 users under the default Premium policy.
  - Recorded whenever UAL ingestion is on.
  - CONFIRMED (P1, P2).

## 9. Microsoft Entra sign-in logs

- **Types (E2), CONFIRMED.** Interactive user, non-interactive user, service principal, managed identity. The legacy sign-in experience shows interactive sign-ins only.
- **Non-interactive sign-ins (E3), CONFIRMED:**
  - **What they are:** made by clients on the user's behalf, such as refresh-token and authorisation-code redemption, SSO, and FOCI.
  - **Aggregation:** rows are combined when Application, User, IP address, Status and Resource ID match. The admin-centre time aggregate is 1, 6 or 24 hours.
  - **IP caveat:** for confidential clients the logged IP is the **original token-issuance IP**, not the IP of the refresh.
  - Since **2025-04-11**, FIDO2 sign-ins that obtain a refresh token are logged as non-interactive.
- **Service principal sign-ins (E4), CONFIRMED:**
  - Sign-ins by apps and service principals using their own credential. Managed identities are logged separately.
  - Rows are aggregated by service principal name or ID, status, IP and resource.
- **Retention (E1), CONFIRMED:**
  - **Free: 7 days. P1: 30 days. P2: 30 days.**
  - Risky sign-ins: Free 7, P1 30, P2 90 days.
  - MFA usage: 30 days for all tiers.
  - Retention changes are **not retroactive**. After upgrading from Free, at most 7 days of history is available.
- **Collection start (E1), CONFIRMED.**
  - P1/P2/Workload ID Premium: from sign-up.
  - **Free:** from the first time Entra ID is opened or the reporting APIs are used.
- **Licence:**
  - The E8/E7 tables list "Sign-in logs: Free = Yes". CONFIRMED.
  - Graph API: "access data for your Microsoft Entra ID P1 or P2 tenants" (E7), and "Downloading logs programmatically with Microsoft Graph requires a premium license" (E6). CONFIRMED.
  - **Whether Free tenants see non-interactive, service-principal and managed-identity sign-ins in the admin centre is not stated (UNCONFIRMED).** The tables do not break licensing down by type.
- **Graph behaviour (E9, beta):**
  - Only **interactive** sign-ins are returned unless the request filters on `signInEventTypes` (`nonInteractiveUser`, `servicePrincipal`, `managedIdentity`).
  - Page size is at most 1,000. Only data within the retention period is returned. Results are newest first.
  - CONFIRMED.
- **Separate from the UAL:** Entra logs are separate from the UAL, and UAL retention does not depend on Entra licensing (E1). CONFIRMED.
  - Purview Audit (Premium) can keep Entra ID *audit* logs beyond the Entra default (E1).
  - Longer retention otherwise needs Azure Monitor: a storage account, Log Analytics or Event Hub.
- **Microsoft Graph activity logs:** P1/P2 only, and not kept unless streamed to storage or analytics tools (E1). CONFIRMED.

## 10. Microsoft Entra audit logs

- **Records (E5), CONFIRMED.** Changes to users, groups, applications, service principals and licences, custom security attributes, and agents.
  - Details include correlation ID, actor and target, and old and new values.
  - The IP address is the OAuth client's IP, meaning the TCP peer of the service endpoint.
  - Entries written back by Exchange Online appear as "Microsoft Substrate Management".
- **Retention (E1), CONFIRMED.** Free 7 days; P1/P2 30 days.
- **Licence:** Free = Yes (E8). "Audit logs are available for features that you have licensed" (E7). Programmatic Graph access needs P1/P2 (E6, E7). CONFIRMED.

## 11. Entra admin-centre download limits (E6)

- **Per file:** up to **100,000** sign-in or provisioning records, and up to **250,000** audit records. The browser download times out on larger sets. CONFIRMED.
- **Format:** CSV or JSON, with UTC timestamps. CONFIRMED.
  - Downloads contain **all columns**, whatever columns were chosen in the UI, but they honour filters.
  - Download is available in all editions.
- **Sign-in download choices:** interactive; interactive (authentication details only); non-interactive; non-interactive (authentication details only); application sign-ins; managed identity. CONFIRMED.
  - **Exact downloaded file names are not documented (UNCONFIRMED).**

## 12. Purview audit search and export (P6, P8)

- Export caps, date range, concurrency, job retention and run time are in the limits table in §1. CONFIRMED.
- **Export columns:**
  - P8 describes the exported CSV as having four columns: **CreationDate, UserIds, Operations, AuditData**, where AuditData is JSON. CONFIRMED (as documented).
  - **Whether New Search exports include extra columns** (for example RecordId, RecordType, AssociatedAdminUnits) is **UNCONFIRMED**. Check against a real export.
- **Excel tip:** Power Query builds JSON columns from the first 1,000 rows only (P8). CONFIRMED.
- **Admin units:** restricted admins cannot see non-user or system-account records. Some operations are visible only to unrestricted admins. (P6) CONFIRMED.

## 13. `Search-UnifiedAuditLog` limits (P11)

- Default 100 records; `-ResultSize` maximum 5,000. CONFIRMED.
- `ReturnLargeSet` pages up to 50,000 results, unsorted. `ReturnNextPreviewPage` is date-sorted with a 5,000 maximum. Mixing them on one SessionId caps output at 10,000. CONFIRMED.
  - **So "5,000 per call, 50,000 per session with ReturnLargeSet" is correct.**
- **Progress fields:** `ResultIndex`, `ResultCount`, and `AuditSearchRequestMetadata.moreRecordsAvailable`. CONFIRMED.
- **Dates:**
  - Values without a time zone are UTC.
  - A date without a time means midnight.
  - The same date for start and end with no time returns nothing.
  - CONFIRMED.
- Microsoft recommends the Management Activity API instead of scripted `Search-UnifiedAuditLog` for bulk download. CONFIRMED.
- In Office 365 operated by 21Vianet the cmdlet returns no results. CONFIRMED.
- **Collector-reported, not on Learn (UNCONFIRMED):** Invictus-IR's V4.1.0 release notes (2026-05-06) say `ResultCount` no longer reports the total population size. Their collector therefore moved to non-session calls capped at 5,000 that shrink the time window when the cap is hit.

## 14. Ingestion latency

- Core services: "typically 60 to 90 minutes"; other services may be longer; Microsoft gives no guarantee (P6). CONFIRMED.
- Turning auditing on: up to 60 minutes, and events may take several hours to become searchable (P4). Premium insights: within 24 hours of enabling the service plan (P7). CONFIRMED.
- Entra sign-in and audit latency: **UNCONFIRMED** (not on the fetched pages).

## 15. UAL record-type values useful for parsing (P12)

All CONFIRMED.

| Name | Value | Meaning |
|---|---|---|
| ExchangeAdmin | 1 | Exchange admin audit log |
| ExchangeItem | 2 | Mailbox audit: action on a single item |
| ExchangeItemGroup | 3 | Mailbox audit: action on multiple items |
| SharePoint | 4 | SharePoint events |
| SharePointFileOperation | 6 | SharePoint file operations |
| AzureActiveDirectory | 8 | Entra ID events |
| AzureActiveDirectoryAccountLogon | 9 | Deprecated |
| SharePointSharingOperation | 14 | SharePoint sharing |
| AzureActiveDirectoryStsLogon | 15 | STS logon |
| ExchangeItemAggregated | 50 | MailItemsAccessed |
| SharePointSearch | 102 | SharePoint home-site search |

Common schema fields (`CreationTime` is UTC): `Id`, `RecordType`, `CreationTime`, `Operation`, `OrganizationId`, `UserType`, `UserKey`, `Workload`, `ResultStatus`, `ObjectId`, `UserId`, `ClientIP`.

---

## Derived notes for evidence-gap reasoning

These are inferences from the confirmed facts above, not Microsoft statements.

- An empty UAL from a Business Basic, Standard or Premium tenant, or an unmanaged trial tenant, may simply mean auditing was never turned on. Ask for `UnifiedAuditLogIngestionEnabled`, taken from Exchange Online PowerShell, and for any `Set-AdminAuditLogConfig` audit records.
- For a window that ends less than about 90 minutes before collection, assume the core-service UAL is incomplete. Other workloads may lag longer.
- With a Free Entra tenant, sign-in evidence older than 7 days is gone unless it was streamed out. Graph collectors fail without P1/P2, so an exported sign-in file is likely to come from an admin-centre download, which is capped at 100,000 records per file.
- When retention is reasoned about by date, records created before 2023-10-17 under Audit (Standard) had 90-day retention.
- Missing MailItemsAccessed, Send or SearchQueryInitiated records can have several causes. These include licence history, a customised `DefaultAuditSet`, audit bypass, Exchange search auditing never being enabled, and a resource or public-folder mailbox. Treat their absence as weak evidence.

## Open questions

1. When exactly did MailItemsAccessed, Send and SearchQueryInitiated* reach general availability for Audit (Standard), and for which SKUs? T1 gives only a public-preview statement (May 2024). Learn shows the current state without a date.
2. Is the "January 2019" start of mailbox auditing on by default documented anywhere on Learn today? Only a March 2019 Tech Community post was found.
3. Is the DiscoverySearch mailbox, or any other system mailbox, excluded from default mailbox auditing? P3 lists only public folder and resource mailboxes as unsupported.
4. Does MailItemsAccessed throttling (more than 1,000 records in 24 hours, `IsThrottled`) still exist? It is no longer on P5.
5. Is the T1 requirement to set `AuditEnabled $true` on Standard-licensed mailboxes still current? It is not on Learn.
6. Do Free Entra tenants see non-interactive, service-principal and managed-identity sign-ins in the admin centre and in its downloads?
7. What file names and column sets does the Entra admin-centre sign-in download produce for each option?
8. Which columns does a Purview New Search CSV export contain today? P8 documents four.
9. Does the fixed one-year retention for non-user entities apply to tenants without Audit (Premium)?
10. What licence SKUs include Audit (Standard)? Learn defers to aka.ms/M365EnterprisePlans, which was not checked.
11. What latency does Microsoft document for Entra sign-in and audit logs (portal and Graph)?
12. Exactly how does the Audit Search Graph API (`/security/auditLog/queries`) limit results? It was not researched here.
