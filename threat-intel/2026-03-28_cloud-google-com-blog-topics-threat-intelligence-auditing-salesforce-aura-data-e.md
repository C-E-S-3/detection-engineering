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
- **Aura Endpoint**: `serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData` (used to retrieve backend Salesforce database object configurations)
- **Aura Endpoint**: `serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems` (used to retrieve object records with sorting and pagination capabilities)
- **Aura Endpoint**: `serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews` (used to check for associated record list components)
- **Aura Endpoint**: `serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData` (used to retrieve home URLs for administration or configuration panels)
- **Aura Endpoint**: `apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled` (used to check if self-registration is enabled)
- **Aura Endpoint**: `apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl` (used to retrieve the self-registration URL)

## 2. TTPs (MITRE ATT&CK Mapping)

- **Tactic**: Initial Access  
  **Technique**: Exploit Public-Facing Application (T1190)  
  **Description**: Exploiting misconfigured Salesforce Aura endpoints to gain unauthorized access to sensitive data, such as credit card numbers, identity documents, and health information.

- **Tactic**: Collection  
  **Technique**: Data from Information Repositories (T1213)  
  **Description**: Using the `getConfigData` and `getItems` Aura methods to retrieve sensitive data from Salesforce objects.

- **Tactic**: Discovery  
  **Technique**: Application Window Discovery (T1010)  
  **Description**: Using the `getInitialListViews` Aura method to identify record lists and associated objects.

- **Tactic**: Discovery  
  **Technique**: Application Layer Protocol (T1071)  
  **Description**: Leveraging the GraphQL API to bypass Salesforce's 2,000-record retrieval limit and retrieve additional records.

- **Tactic**: Credential Access  
  **Technique**: Account Discovery (T1087)  
  **Description**: Using the `getIsSelfRegistrationEnabled` and `getSelfRegistrationUrl` methods to identify and exploit self-registration functionality.

## 3. Malware & Tools

- **Tool**: AuraInspector  
  **Description**: An open-source command-line tool developed by Mandiant to identify and audit access control misconfigurations in Salesforce Aura.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor**: Not explicitly attributed to a specific group. However, the techniques described are commonly used by attackers to exploit misconfigured Salesforce environments.
- **Targeted Sectors**: Organizations using Salesforce Experience Cloud, particularly those handling sensitive data such as credit card numbers, identity documents, and health information.

## 5. Splunk Detection Searches

### Detecting Unauthorized Access to Aura Endpoints
```spl
index=proxy OR index=web
| search uri_path="/serviceComponent://ui.force.components.controllers.*"
| stats count by uri_path, src_ip
| where count > 10
| table uri_path, src_ip, count
```
*Comment: This search identifies potential unauthorized access to Salesforce Aura endpoints by looking for unusual activity patterns.*

### Detecting GraphQL API Usage
```spl
index=proxy OR index=web
| search uri_path="/graphql"
| stats count by uri_path, src_ip
| where count > 10
| table uri_path, src_ip, count
```
*Comment: This search identifies potential abuse of the GraphQL API for data exfiltration.*

### Detecting Self-Registration Activity
```spl
index=proxy OR index=web
| search uri_path="/applauncher.LoginFormController/ACTION$getSelfRegistrationUrl"
| stats count by uri_path, src_ip
| where count > 5
| table uri_path, src_ip, count
```
*Comment: This search identifies attempts to access the self-registration URL, which could indicate reconnaissance or exploitation attempts.*

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, to help identify and audit access control misconfigurations in Salesforce's Aura framework. The report highlights several previously undocumented techniques, including the use of GraphQL to bypass Salesforce's 2,000-record retrieval limit and the exploitation of misconfigured Aura endpoints to access sensitive data. Organizations using Salesforce Experience Cloud should immediately review their access control configurations, disable unnecessary self-registration, and monitor for unusual activity on Salesforce endpoints and APIs. The provided Splunk detection searches can assist in identifying potential abuse of these techniques.