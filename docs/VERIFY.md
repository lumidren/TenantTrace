# To verify against real exports

TenantTrace was built without access to a Microsoft 365 tenant. Every format detail and fact
below is implemented from best knowledge because Microsoft documentation does not state it (or
contradicts itself). Each item says what TenantTrace currently assumes, where it is used, and
what to look at in a real export to confirm or correct it. The research notes behind each item
are in `docs/sources/` (section numbers in brackets).

When you have a real export, put it in `samples/real/` (git-ignored) and run
`tenanttrace ingest samples/real --case <somewhere outside the repo>`; the manifest and
processing log show which parser was chosen and how many records were not recognised.

## Export layouts

| # | Assumption | Used by | Check in a real export | Notes |
|---|-----------|---------|------------------------|-------|
| F1 | The current Purview audit export may have 8 columns: `RecordId, CreationDate, RecordType, Operation, UserId, AuditData, AssociatedAdminUnits, AssociatedAdminUnitsNames`. Microsoft documents only the 4-column layout `CreationDate, UserIds, Operations, AuditData`. | parser `purview_ual_csv`, generator format `purview_ual_csv_v2` | header row of a Purview search-job CSV | [formats 1a-1, 1a-2] Parser accepts both. |
| F2 | Purview `CreationDate` is ISO 8601 UTC with 7 fractional digits and `Z`. | display only; times come from `AuditData.CreationTime` | any row | [1a-3] |
| F3 | `Search-UnifiedAuditLog \| Export-Csv` writes `RunspaceId, RecordType, CreationDate, UserIds, Operations, AuditData, ResultIndex, ResultCount, Identity, IsValid, ObjectState` in that order, `RecordType` as a name, `CreationDate` in the session culture (en-US assumed), and optionally a `#TYPE` first line. | parser `ps_ual_csv`, generator | header and first rows | [1b-1] Parser matches columns by name, accepts integer or name RecordType, skips any `#TYPE` line. |
| F4 | `Identity` in the PowerShell export equals `AuditData.Id`. | not relied on (dedup uses `AuditData.Id`) | compare the two columns | [1b-1] |
| F5 | `ResultCount` is the total number of hits, so `ResultCount` larger than the rows present means an incomplete export. Invictus-IR's v4.1.0 notes say `ResultCount` no longer reports the total. | truncation check | a known-complete small export | [1b-2, retention 13] TenantTrace reports this as "possible truncation", citing the evidence. |
| F6 | Entra sign-in CSV header list (53 columns) and its casing. | parser `entra_signin_csv` | header row of InteractiveSignIns and NonInteractiveSignIns downloads | [2a-2] Parser matches case-insensitively and needs only a core subset. |
| F7 | Entra CSV `Date (UTC)` is ISO 8601 with `Z`; `Location` is `City, State, CC`; `Compliant`/`Managed` are `Yes`/`No`; `Authentication requirement` holds `singleFactorAuthentication`/`multiFactorAuthentication` (or a friendly form). | parser `entra_signin_csv` | rows with each value | [2a-5] Parser accepts friendly forms too. |
| F8 | The Entra JSON download is an array of Graph **beta** `signIn` objects (camelCase). | parser `entra_signin_json` | a JSON download | [2b-1] |
| F9 | `AppAccessContext` is a single object and `IssuedAtTime` is an ISO time. | session linking | MailItemsAccessed and Exchange admin records | [1c-4] Parser accepts an object or an array. |
| F10 | Multi-valued inbox-rule parameters (`ForwardTo`, `SubjectContainsWords`) are joined with `;` and switches are `True`. | inbox rule normalization | a `New-InboxRule` record with several keywords | [1d-3] Parser splits on `;` and `,`. |
| F11 | `UpdateInboxRules` records carry rule details in `OperationProperties` (`RuleName`, `RuleActions`, ...). | inbox rule normalization (best effort) | a rule created in Outlook desktop | [1d-4] |
| F12 | STS logon records use `ErrorNumber` (Microsoft documents `ErrorCode`), `ExtendedProperties` keys `UserAgent`, `RequestType`, `ResultStatusDetail`, and `DeviceProperties` names such as `SessionId`. `UserLoggedIn` has RecordType 15. | UAL sign-in normalization | a `UserLoggedIn` record | [1g-2] Parser accepts both error fields. |
| F13 | Directory operations in the UAL end with a period: `Consent to application.`, `User registered security info.`, `User changed default security info.`, `User deleted security info.`, `Register device.`, `Add registered owner to device.`, `Add delegated permission grant.`. | action mapping | the Operation column for those activities | [1g-3] Mapping ignores case and a trailing period. |
| F14 | Consent scopes are in `ModifiedProperties` `ConsentAction.Permissions` as free text containing `Scope: <space-separated scopes>`; the consented app ID is in `TargetId.ServicePrincipalNames`. | TT-APP-001, TT-APP-002, pivot by app ID | a `Consent to application.` record | [1g-4] Parser extracts scopes defensively and also scans `Target`. |
| F15 | The security-info method is named in `ExtendedProperties` (`Method` or `AdditionalInfo`). | TT-AUTH-001 summary only | a `User registered security info.` record | [1g-3] |
| F16 | `TargetUserOrGroupType` values include `Member`, `Guest`, `Group`, `Partner`, `SharePointGroup`, `SecurityGroup`. | external-sharing check | sharing records | [1f-3] External is decided from the target's domain, not only this field. |
| F17 | Microsoft-Extractor-Suite `Get-UAL -Output JSON` writes wrapper objects with `CreationDate` as `/Date(ms)/` (Windows PowerShell 5.1) in UTF-8 with BOM; sign-in pages are appended to one file as concatenated arrays. | parsers `ual_json`, `entra_signin_json` | a collector output folder | [collectors 1.3, 1.4] Reader accepts concatenated arrays, JSON Lines and single objects. |

## Reference table facts

| # | Entry (`gap_reference.yaml`) | Unverified statement |
|---|------------------------------|----------------------|
| R1 | `entra_signin_noninteractive` | whether Microsoft Entra ID Free tenants can see and download non-interactive sign-ins |
| R2 | `ual_azuread_logon` | the record type of `UserLoggedIn` (documented only for `UserLoginFailed`) |
| R3 | `ual_azuread` | the UAL spelling (trailing period) of consent, security-info and device operation names |
| R4 | `ual_mailbox_items` | the date MailItemsAccessed moved from Audit (Premium) to Audit (Standard); whether `IsThrottled` throttling still applies |

The report lists unverified entries next to every gap that relies on them.

## Synthetic data only

These values appear only in generated test data, never in TenantTrace's reasoning:

- Microsoft first-party application IDs used for realistic sign-ins (OfficeHome, Microsoft Office,
  Outlook Mobile, Teams, OneDrive SyncEngine, Exchange REST PowerShell).
- City coordinates in `src/ttcorpus/model.py` are approximate public values.
