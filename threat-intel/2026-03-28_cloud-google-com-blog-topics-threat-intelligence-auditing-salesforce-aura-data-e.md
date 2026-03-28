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

### Tactic: Collection (TA0009)
- **Technique ID**: T1213.001
  **Technique Name**: Data from Information Repositories: Local Data Staging
  **Description**: The Salesforce Aura framework allows attackers to exploit misconfigured access controls to retrieve sensitive data, such as credit card numbers and identity documents, using legitimate Aura methods like `getConfigData` and `getItems`.

### Tactic: Discovery (TA0007)
- **Technique ID**: T1087.002
  **Technique Name**: Account Discovery: Domain Accounts
  **Description**: Misconfigured Salesforce Aura methods, such as `getConfigData` and `getItems`, can allow attackers to enumerate user accounts and associated data.

### Tactic: Collection (TA0009)
- **Technique ID**: T1530
  **Technique Name**: Data from Cloud Storage Object
  **Description**: Attackers can use the Salesforce GraphQL API to retrieve large amounts of data from misconfigured objects, bypassing the 2,000-record limit imposed by other methods.

### Tactic: Credential Access (TA0006)
- **Technique ID**: T1078
  **Technique Name**: Valid Accounts
  **Description**: Attackers can exploit misconfigured self-registration settings in Salesforce to create unauthorized accounts, potentially gaining access to sensitive data.

## 3. Malware & Tools

### Tools
- **AuraInspector**: An open-source tool released by Mandiant to identify and audit access control misconfigurations and potential data exposures in the Salesforce Aura framework.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor**: Not specified
- **Campaign Name**: Not specified
- **Motivations**: Likely financial gain or data theft, given the focus on accessing sensitive data such as credit card numbers and identity documents.
- **Targeted Sectors/Geographies**: Organizations using Salesforce Experience Cloud, potentially across various sectors.

## 5. Splunk Detection Searches

### Detecting Misuse of `getConfigData` Aura Method
```spl
index=proxy_logs
| search uri_path="*/serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData"
| stats count by src_ip, user, uri_path
| where count > 10
| table src_ip, user, uri_path, count
```
*Comment: This search identifies potential misuse of the `getConfigData` Aura method by looking for repeated requests to the specific URI path.*

### Detecting Misuse of `getItems` Aura Method
```spl
index=proxy_logs
| search uri_path="*/serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems"
| stats count by src_ip, user, uri_path
| where count > 10
| table src_ip, user, uri_path, count
```
*Comment: This search identifies potential misuse of the `getItems` Aura method by analyzing repeated requests to the relevant URI path.*

### Detecting GraphQL API Abuse
```spl
index=proxy_logs
| search uri_path="*/graphql"
| stats count by src_ip, user, uri_path
| where count > 10
| table src_ip, user, uri_path, count
```
*Comment: This search identifies potential abuse of the Salesforce GraphQL API by monitoring for repeated requests to the GraphQL endpoint.*

### Detecting Self-Registration Exploitation
```spl
index=proxy_logs
| search uri_path="*/apex/applauncher.LoginFormController/ACTION$getSelfRegistrationUrl"
| stats count by src_ip, user, uri_path
| where count > 5
| table src_ip, user, uri_path, count
```
*Comment: This search identifies potential exploitation of self-registration settings by monitoring for requests to the self-registration URL endpoint.*

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, to help organizations identify and audit access control misconfigurations in the Salesforce Aura framework. These misconfigurations can expose sensitive data, such as credit card numbers and identity documents, to unauthorized users. The report also highlights a previously undocumented technique using the Salesforce GraphQL API to bypass the 2,000-record retrieval limit, which could be exploited in cases of misconfiguration. Organizations using Salesforce are advised to review their access control settings, disable self-registration if not required, and monitor for suspicious activity targeting Salesforce Aura methods and APIs.