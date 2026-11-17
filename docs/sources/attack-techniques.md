# MITRE ATT&CK techniques used by TenantTrace

- **Retrieved:** 2026-11-17, from attack.mitre.org.
- **Method:** each technique page was fetched and its HTML `<title>`, object "Version" and "Last Modified" fields read. Names below are copied exactly from the page titles, including capitalisation such as "Sharepoint".
- **ATT&CK version shown on the site:** **ATT&CK v20.1**. https://attack.mitre.org/resources/versions/ lists it as "Current Version", in effect from **October 13, 2026**. The previous version, v19.2, ran from April 28 to October 12, 2026. The updates page shows "Updates - October 2026". CONFIRMED.

| # | ID | Exact name on attack.mitre.org | Type | Object version | Last modified (page) | URL | Status |
|---|---|---|---|---|---|---|---|
| 1 | T1078.004 | Valid Accounts: Cloud Accounts | Sub-technique | 2.0 | 12 May 2026 | https://attack.mitre.org/techniques/T1078/004/ | CONFIRMED |
| 2 | T1566.002 | Phishing: Spearphishing Link | Sub-technique | 2.8 | 04 November 2026 | https://attack.mitre.org/techniques/T1566/002/ | CONFIRMED |
| 3 | T1114.002 | Email Collection: Remote Email Collection | Sub-technique | 1.4 | 09 September 2026 | https://attack.mitre.org/techniques/T1114/002/ | CONFIRMED |
| 4 | T1114.003 | Email Collection: Email Forwarding Rule | Sub-technique | 1.4 | 03 November 2026 | https://attack.mitre.org/techniques/T1114/003/ | CONFIRMED |
| 5 | T1564.008 | Hide Artifacts: Email Hiding Rules | Sub-technique | 2.0 | 04 November 2026 | https://attack.mitre.org/techniques/T1564/008/ | CONFIRMED |
| 6 | T1098.002 | Account Manipulation: Additional Email Delegate Permissions | Sub-technique | 2.2 | 24 October 2025 | https://attack.mitre.org/techniques/T1098/002/ | CONFIRMED |
| 7 | T1098.005 | Account Manipulation: Device Registration | Sub-technique | 1.4 | 04 November 2026 | https://attack.mitre.org/techniques/T1098/005/ | CONFIRMED |
| 8 | T1098.001 | Account Manipulation: Additional Cloud Credentials | Sub-technique | 2.8 | 04 November 2026 | https://attack.mitre.org/techniques/T1098/001/ | CONFIRMED |
| 9 | T1556.006 | Modify Authentication Process: Multi-Factor Authentication | Sub-technique | 2.0 | 04 November 2026 | https://attack.mitre.org/techniques/T1556/006/ | CONFIRMED |
| 10 | T1528 | Steal Application Access Token | Technique | 1.5 | 12 May 2026 | https://attack.mitre.org/techniques/T1528/ | CONFIRMED |
| 11 | T1550.001 | Use Alternate Authentication Material: Application Access Token | Sub-technique | 2.0 | 03 November 2026 | https://attack.mitre.org/techniques/T1550/001/ | CONFIRMED |
| 12 | T1550.004 | Use Alternate Authentication Material: Web Session Cookie | Sub-technique | 2.0 | 12 May 2026 | https://attack.mitre.org/techniques/T1550/004/ | CONFIRMED |
| 13 | T1539 | Steal Web Session Cookie | Technique | 1.5 | 03 November 2026 | https://attack.mitre.org/techniques/T1539/ | CONFIRMED |
| 14 | T1530 | Data from Cloud Storage | Technique | 2.2 | 03 November 2026 | https://attack.mitre.org/techniques/T1530/ | CONFIRMED |
| 15 | T1213.002 | Data from Information Repositories: Sharepoint | Sub-technique | 1.2 | 07 October 2026 | https://attack.mitre.org/techniques/T1213/002/ | CONFIRMED |
| 16 | T1537 | Transfer Data to Cloud Account | Technique | 1.5 | 24 October 2025 | https://attack.mitre.org/techniques/T1537/ | CONFIRMED |
| 17 | T1567 | Exfiltration Over Web Service | Technique | 1.5 | 12 May 2026 | https://attack.mitre.org/techniques/T1567/ | CONFIRMED |
| 17a | T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | Sub-technique (cloud storage) | 1.3 | 12 May 2026 | https://attack.mitre.org/techniques/T1567/002/ | CONFIRMED |
| 18 | T1110.003 | Brute Force: Password Spraying | Sub-technique | 1.8 | 04 November 2026 | https://attack.mitre.org/techniques/T1110/003/ | CONFIRMED |
| 19 | T1621 | Multi-Factor Authentication Request Generation | Technique | 1.2 | 24 October 2025 | https://attack.mitre.org/techniques/T1621/ | CONFIRMED |
| 20 | T1557 | Adversary-in-the-Middle | Technique | 2.5 | 03 November 2026 | https://attack.mitre.org/techniques/T1557/ | CONFIRMED |
| 21 | T1534 | Internal Spearphishing | Technique | 1.4 | 12 May 2026 | https://attack.mitre.org/techniques/T1534/ | CONFIRMED |

## Notes

- **Naming:** use the page-title spelling exactly. Note "Sharepoint" (lower-case p) in T1213.002, the hyphens in "Adversary-in-the-Middle", and "Multi-Factor" with a hyphen in T1556.006 and T1621.
- **T1530 name:** current name is "Data from Cloud Storage".
- **Display convention:** sub-techniques are shown as "Parent: Child", matching the site titles. In STIX data the sub-technique `name` field holds only the child part, for example "Cloud Accounts".
- **Deprecation check:** none of the 22 pages showed a deprecation or revocation notice in the title. The page body was not checked in full.
- **Scope:** this table confirms IDs and names only. **Tactic assignments, platforms, detection guidance and data components were not researched here.** Fetch them separately if TenantTrace reports tactics.

## Open questions

1. Several pages show "Last Modified" dates of 3–4 November 2026. That is later than the October 13, 2026 start date listed for v20.1 on the versions page. Has a later point release been published, or are these STIX authoring timestamps? Check before pinning a version string in reports.
2. Should TenantTrace record the ATT&CK version in its output? If so, should it pin to "v20.1" and to these object versions, so that later renames can be detected?
3. Tactic mapping for each technique was not verified. For example, T1078.004 maps to several tactics.
