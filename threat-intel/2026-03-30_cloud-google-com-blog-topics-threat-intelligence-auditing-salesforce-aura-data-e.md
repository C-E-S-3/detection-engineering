---
scraped_at: 2026-01-12T00:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure/
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### Domains/URLs
- None identified.

### File Hashes
- None identified.

### IP Addresses
- None identified.

### Other IOCs
- None identified.

## 2. TTPs (MITRE ATT&CK Mapping)

### Tactics and Techniques
- **Tactic:** Collection
  - **Technique ID:** T1530
  - **Technique Name:** Data from Cloud Storage Object
  - **Description:** Exploiting misconfigurations in Salesforce Aura to retrieve sensitive data such as credit card numbers, identity documents, and health information.

- **Tactic:** Discovery
  - **Technique ID:** T1087.002
  - **Technique Name:** Account Discovery: Domain Accounts
  - **Description:** Using Salesforce Aura methods to enumerate accounts and retrieve object records.

- **Tactic:** Collection
  - **Technique ID:** T1074.001
  - **Technique Name:** Data Staged: Local Data Staging
  - **Description:** Leveraging GraphQL API to bypass Salesforce’s 2,000-record retrieval limit and collect large datasets.

- **Tactic:** Defense Evasion
  - **Technique ID:** T1562.001
  - **Technique Name:** Impair Defenses: Disable or Modify Tools
  - **Description:** Exploiting misconfigured access controls to bypass standard Salesforce object sharing rules.

## 3. Malware & Tools

### Tools
- **AuraInspector**: An open-source tool released by Mandiant to identify and audit access control misconfigurations in Salesforce Aura.

## 4. Threat Actor / Campaign Attribution
- **Threat Actor:** Not explicitly attributed.
- **Campaign Name:** Not specified.
- **Motivations:** Likely financial or espionage-related, targeting sensitive data such as credit card numbers, identity documents, and health information.
- **Targeted Sectors/Geographies:** Organizations using Salesforce Experience Cloud, potentially across various industries.

## 5. Splunk Detection Searches

### Behavioral TTPs

#### Detecting Misconfigured Aura Methods
```spl
index=web sourcetype="http:access" uri_path="/aura" http_method=POST
| spath input=_raw output=actions
| search actions="*getConfigData*" OR actions="*getItems*" OR actions="*getInitialListViews*"
| stats count by clientip, uri_path, actions
| where count > 10
```
*Comment:* Detects repeated use of misconfigured Aura methods such as `getConfigData`, `getItems`, and `getInitialListViews`.

#### Detecting GraphQL API Abuse
```spl
index=web sourcetype="http:access" uri_path="/graphql" http_method=POST
| spath input=_raw output=query
| search query="*{*}" AND query="*records*"
| stats count by clientip, uri_path, query
| where count > 5
```
*Comment:* Identifies potential abuse of the GraphQL API to retrieve large datasets.

#### Detecting Bulk Actions in Salesforce Aura
```spl
index=web sourcetype="http:access" uri_path="/aura" http_method=POST
| spath input=_raw output=actions
| search actions="*bulk*"
| stats count by clientip, uri_path, actions
| where count > 50
```
*Comment:* Flags excessive bulk actions in Salesforce Aura, which may indicate misuse.

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, to help organizations identify and audit access control misconfigurations in Salesforce Aura. These misconfigurations can expose sensitive data such as credit card numbers and health information. Additionally, attackers can exploit Salesforce Aura’s GraphQL API to bypass record retrieval limits and collect large datasets. Organizations using Salesforce Experience Cloud should immediately review their access control configurations, disable self-registration if not required, and monitor for suspicious activity involving Aura methods and GraphQL API endpoints.