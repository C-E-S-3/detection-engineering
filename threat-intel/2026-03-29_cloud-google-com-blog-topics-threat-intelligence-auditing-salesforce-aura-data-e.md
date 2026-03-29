---
scraped_at: 2026-01-12T00:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure/
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### Domains/URLs
- None identified

### IP Addresses
- None identified

### File Hashes
- None identified

### Email Addresses
- None identified

### File Names/Paths
- None identified

### Registry Keys
- None identified

### Mutex Names
- None identified

### C2 Infrastructure
- None identified

## 2. TTPs (MITRE ATT&CK Mapping)

### Tactic: Collection
- **Technique ID:** T1213.001
  **Technique Name:** Data from Information Repositories: Local Data Staging
  **Description:** Misconfigured Salesforce Aura endpoints allow unauthorized access to sensitive data such as credit card numbers, identity documents, and health information.

### Tactic: Discovery
- **Technique ID:** T1087
  **Technique Name:** Account Discovery
  **Description:** Misconfigured access controls allow attackers to retrieve records of Salesforce objects, including user accounts.

### Tactic: Collection
- **Technique ID:** T1074.001
  **Technique Name:** Data Staged: Local Data Staging
  **Description:** Attackers can use the GraphQL API to bypass Salesforce's 2,000-record retrieval limit and access additional records.

### Tactic: Credential Access
- **Technique ID:** T1078
  **Technique Name:** Valid Accounts
  **Description:** Exploiting self-registration misconfigurations to gain unauthorized access to Salesforce instances.

## 3. Malware & Tools

### Tools
- **AuraInspector:** An open-source tool released by Mandiant to identify and audit access control misconfigurations in Salesforce Aura framework.

## 4. Threat Actor / Campaign Attribution
- **Threat Actor:** Not explicitly mentioned.
- **Campaign Name:** Not explicitly mentioned.
- **Motivations:** Likely financial gain or data theft, targeting sensitive data such as credit card numbers, identity documents, and health information.
- **Targeted Sectors/Geographies:** Organizations using Salesforce Experience Cloud.

## 5. Splunk Detection Searches

### Detecting Misconfigured Aura Endpoints
```spl
index=web sourcetype=access_combined
| search "POST /aura" "serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData"
| stats count by src_ip, http_user_agent
| sort -count
```
*# This search identifies POST requests to the Aura endpoint with the `getConfigData` method, which may indicate attempts to exploit misconfigured access controls.*

### Detecting GraphQL API Misuse
```spl
index=web sourcetype=access_combined
| search "POST /graphql" "query"
| stats count by src_ip, http_user_agent
| sort -count
```
*# This search identifies POST requests to the GraphQL API, which could indicate attempts to exploit the API for unauthorized data access.*

### Detecting Self-Registration Exploitation
```spl
index=web sourcetype=access_combined
| search "POST /applauncher.LoginFormController/ACTION$getSelfRegistrationUrl"
| stats count by src_ip, http_user_agent
| sort -count
```
*# This search identifies attempts to access self-registration URLs, which may indicate exploitation of misconfigured self-registration settings.*

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, to help organizations identify and mitigate access control misconfigurations in Salesforce's Aura framework. These misconfigurations can expose sensitive data, including credit card numbers and personal information, to unauthorized users. Additionally, attackers can exploit Salesforce's GraphQL API to bypass record retrieval limits and access a larger dataset. Organizations using Salesforce should immediately audit their access control configurations, disable self-registration if not required, and monitor for suspicious activity targeting the Aura and GraphQL endpoints.