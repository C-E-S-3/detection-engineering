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

### Other IOCs
- None identified

## 2. TTPs (MITRE ATT&CK Mapping)

### Tactic: Collection
- **Technique ID**: T1530 - Data from Cloud Storage Object
  - **Description**: The Salesforce Aura framework was found to have misconfigurations that could allow unauthorized access to sensitive data, including credit card numbers, identity documents, and health information.

### Tactic: Discovery
- **Technique ID**: T1087.002 - Account Discovery: Domain Accounts
  - **Description**: The `getConfigData` Aura method can be exploited to retrieve a list of objects used in the backend Salesforce database.
- **Technique ID**: T1087.001 - Account Discovery: Local Account
  - **Description**: The `getItems` Aura method can be used to retrieve records for specific objects, potentially exposing sensitive data if access controls are misconfigured.

### Tactic: Collection
- **Technique ID**: T1530 - Data from Cloud Storage Object
  - **Description**: The GraphQL API can be used to bypass the 2,000-record retrieval limit in Salesforce, allowing attackers to retrieve all records tied to an object if access controls are misconfigured.

### Tactic: Initial Access
- **Technique ID**: T1078.003 - Valid Accounts: Local Accounts
  - **Description**: The `getIsSelfRegistrationEnabled` and `getSelfRegistrationUrl` Aura methods can be used to identify if self-registration is enabled and retrieve the self-registration URL, potentially allowing attackers to create unauthorized accounts.

## 3. Malware & Tools

### Tools
- **AuraInspector**: An open-source command-line tool released by Mandiant to identify and audit access control misconfigurations in the Salesforce Aura framework.

## 4. Threat Actor / Campaign Attribution
- **Threat Actor**: Not specified
- **Campaign Name**: Not specified
- **Motivations**: Exploitation of misconfigured Salesforce Aura endpoints to gain unauthorized access to sensitive data, including credit card numbers, identity documents, and health information.
- **Targeted Sectors/Geographies**: Organizations using Salesforce Experience Cloud, particularly those with misconfigured access controls.

## 5. Splunk Detection Searches

### Detecting Misuse of `getConfigData` Aura Method
```spl
index=your_index sourcetype="your_sourcetype"
| search "serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData"
| stats count by src_ip, user, _time
| sort - count
```
# This search identifies usage of the `getConfigData` Aura method, which can be exploited to retrieve sensitive backend database object information.

### Detecting Misuse of `getItems` Aura Method
```spl
index=your_index sourcetype="your_sourcetype"
| search "serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems"
| stats count by src_ip, user, _time
| sort - count
```
# This search identifies usage of the `getItems` Aura method, which can be exploited to retrieve records for specific objects.

### Detecting Misuse of `getIsSelfRegistrationEnabled` and `getSelfRegistrationUrl` Aura Methods
```spl
index=your_index sourcetype="your_sourcetype"
| search "apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled" OR "apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl"
| stats count by src_ip, user, _time
| sort - count
```
# This search identifies attempts to query the self-registration status and URL, which could indicate reconnaissance activity.

### Detecting GraphQL API Misuse
```spl
index=your_index sourcetype="your_sourcetype"
| search "GraphQL" "query" "User Interface API"
| stats count by src_ip, user, _time
| sort - count
```
# This search identifies usage of the GraphQL API, which could be exploited to bypass record retrieval limits if access controls are misconfigured.

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, to help organizations identify and audit access control misconfigurations in Salesforce's Aura framework. Misconfigurations in Salesforce Experience Cloud applications can expose sensitive data, including credit card numbers and identity documents, to unauthorized users. Attackers can exploit the `getConfigData` and `getItems` Aura methods, as well as the GraphQL API, to retrieve sensitive records and bypass Salesforce's 2,000-record retrieval limit. Additionally, misconfigured self-registration settings can allow attackers to create unauthorized accounts. Organizations using Salesforce should immediately review their access control configurations, disable unnecessary self-registration, and monitor for suspicious activity using the provided Splunk detection searches.

## Recommendations
1. Use the AuraInspector tool to identify and remediate access control misconfigurations in Salesforce Aura.
2. Audit and restrict access to sensitive Salesforce objects and methods, such as `getConfigData` and `getItems`.
3. Disable self-registration if not required and verify that the self-registration page is inaccessible.
4. Monitor for suspicious activity using the provided Splunk detection searches.
5. Regularly review and update Salesforce access control settings to ensure compliance with the principle of least privilege.
