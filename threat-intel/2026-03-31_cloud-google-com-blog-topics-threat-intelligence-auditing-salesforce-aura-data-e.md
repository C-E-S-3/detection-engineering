---
scraped_at: 2026-01-12T00:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure/
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### Domains/URLs
- None identified

### File Hashes
- None identified

### IP Addresses
- None identified

### Other
- None identified

## 2. TTPs (MITRE ATT&CK Mapping)

### Tactics and Techniques
- **Tactic:** Collection
  - **Technique ID:** T1213.001
  - **Technique Name:** Data from Information Repositories: Local Data Repositories
  - **Description:** Misconfigured Salesforce Aura endpoints allow unauthorized access to sensitive data, including credit card numbers and identity documents.

- **Tactic:** Discovery
  - **Technique ID:** T1087.001
  - **Technique Name:** Account Discovery: Local Account
  - **Description:** Attackers can use the `getConfigData` and `getItems` Aura methods to enumerate Salesforce object records and retrieve sensitive data.

- **Tactic:** Initial Access
  - **Technique ID:** T1078
  - **Technique Name:** Valid Accounts
  - **Description:** Exploitation of self-registration misconfigurations to gain authenticated access to Salesforce instances.

- **Tactic:** Collection
  - **Technique ID:** T1025
  - **Technique Name:** Data from Removable Media
  - **Description:** Abuse of GraphQL API to bypass record retrieval limits and access large datasets.

## 3. Malware & Tools

### Tools
- **AuraInspector**: An open-source tool released by Mandiant to audit Salesforce Aura misconfigurations and identify unauthorized data exposures.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor:** Not explicitly attributed to a specific actor.
- **Campaign Name:** Not specified.
- **Motivations:** Likely financial gain or espionage, targeting sensitive business data stored in Salesforce environments.
- **Targeted Sectors/Geographies:** Organizations using Salesforce, particularly those with misconfigured access controls.

## 5. Splunk Detection Searches

### Behavioral TTPs

#### Detecting Misuse of `getConfigData` Aura Method
```spl
index=proxy OR index=web
| search uri_path="*/ACTION$getConfigData"
| stats count by src_ip, uri_path, http_user_agent
| where count > 10
```
*Comment:* Detects repeated use of the `getConfigData` Aura method, which may indicate enumeration attempts.

#### Detecting Misuse of `getItems` Aura Method
```spl
index=proxy OR index=web
| search uri_path="*/ACTION$getItems"
| stats count by src_ip, uri_path, http_user_agent
| where count > 10
```
*Comment:* Detects repeated use of the `getItems` Aura method, which may indicate attempts to retrieve unauthorized records.

#### Detecting GraphQL API Abuse
```spl
index=proxy OR index=web
| search uri_path="*/graphql"
| stats count by src_ip, uri_path, http_user_agent
| where count > 10
```
*Comment:* Identifies potential abuse of the GraphQL API for unauthorized data retrieval.

#### Detecting Self-Registration Page Access
```spl
index=proxy OR index=web
| search uri_path="*/self-registration"
| stats count by src_ip, uri_path, http_user_agent
| where count > 5
```
*Comment:* Monitors access to self-registration pages, which may indicate exploitation of misconfigurations.

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, to help organizations identify and mitigate access control misconfigurations in Salesforce Aura. These misconfigurations can expose sensitive data, such as credit card numbers and identity documents, to unauthorized users. The report highlights the abuse of specific Aura methods (`getConfigData`, `getItems`) and the GraphQL API to bypass Salesforce's record retrieval limits and access sensitive data. Organizations using Salesforce should immediately review their access control configurations, disable self-registration if not required, and monitor for suspicious activity using the provided Splunk detection searches.