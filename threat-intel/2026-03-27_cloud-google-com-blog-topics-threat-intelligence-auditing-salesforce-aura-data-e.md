---
scraped_at: 2026-01-12T00:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure/
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### IP Addresses
- None identified

### Domains/URLs
- None identified

### File Hashes
- None identified

### Other IOCs
- None identified

## 2. TTPs (MITRE ATT&CK Mapping)

### Tactic: Collection (TA0009)
- **Technique ID**: T1530 - **Technique Name**: Data from Cloud Storage Object
  - **Description**: The Salesforce Aura framework's misconfigurations can allow unauthorized access to sensitive data such as credit card numbers, identity documents, and health information.

### Tactic: Discovery (TA0007)
- **Technique ID**: T1087.002 - **Technique Name**: Account Discovery: Domain Accounts
  - **Description**: Misconfigured access controls in Salesforce Aura can allow attackers to enumerate and access user accounts and associated records.

### Tactic: Discovery (TA0007)
- **Technique ID**: T1083 - **Technique Name**: File and Directory Discovery
  - **Description**: Attackers can use the `getInitialListViews` Aura method to identify accessible record lists and associated objects.

### Tactic: Collection (TA0009)
- **Technique ID**: T1213 - **Technique Name**: Data from Information Repositories
  - **Description**: The GraphQL API in Salesforce can be exploited to retrieve all records tied to an object, bypassing the 2,000-record limit imposed by other methods.

### Tactic: Credential Access (TA0006)
- **Technique ID**: T1078 - **Technique Name**: Valid Accounts
  - **Description**: Attackers can exploit misconfigured self-registration settings to create authenticated accounts and gain unauthorized access to sensitive data.

## 3. Malware & Tools

### Tools
- **AuraInspector**: An open-source tool released by Mandiant to identify and audit access control misconfigurations within the Salesforce Aura framework.

## 4. Threat Actor / Campaign Attribution
- **Threat Actor**: Not specified
- **Campaign Name**: Not specified
- **Motivations**: Likely financial gain or data theft, targeting sensitive data such as credit card numbers, identity documents, and health information.
- **Targeted Sectors/Geographies**: Organizations using Salesforce Experience Cloud, potentially across various industries.

## 5. Splunk Detection Searches

### TTP: Data from Cloud Storage Object (T1530)
```spl
index=proxy_logs
| search uri_path="*/serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData"
| stats count by src_ip, user, uri_path
| table src_ip, user, uri_path, count
```
*Comment: Detects unauthorized access to the `getConfigData` Aura method.*

### TTP: Account Discovery: Domain Accounts (T1087.002)
```spl
index=proxy_logs
| search uri_path="*/serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews"
| stats count by src_ip, user, uri_path
| table src_ip, user, uri_path, count
```
*Comment: Identifies potential enumeration of accessible record lists using the `getInitialListViews` Aura method.*

### TTP: Data from Information Repositories (T1213)
```spl
index=proxy_logs
| search uri_path="*/serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems"
| stats count by src_ip, user, uri_path
| table src_ip, user, uri_path, count
```
*Comment: Detects attempts to retrieve records using the `getItems` Aura method.*

### TTP: Valid Accounts (T1078)
```spl
index=proxy_logs
| search uri_path="*/apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled" OR uri_path="*/apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl"
| stats count by src_ip, user, uri_path
| table src_ip, user, uri_path, count
```
*Comment: Monitors for attempts to exploit self-registration methods to create unauthorized accounts.*

### TTP: Data from Information Repositories (T1213) - GraphQL API
```spl
index=proxy_logs
| search uri_path="*/graphql" method=POST
| stats count by src_ip, user, uri_path
| table src_ip, user, uri_path, count
```
*Comment: Detects usage of the GraphQL API to retrieve records from Salesforce objects.*

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, to identify and audit access control misconfigurations in the Salesforce Aura framework. These misconfigurations can allow unauthorized access to sensitive data, including credit card numbers and identity documents. Additionally, attackers can exploit Salesforce's GraphQL API to bypass record retrieval limits and access large datasets. Organizations using Salesforce should immediately review their access control configurations, disable unnecessary self-registration, and monitor for suspicious activity using the provided detection searches.