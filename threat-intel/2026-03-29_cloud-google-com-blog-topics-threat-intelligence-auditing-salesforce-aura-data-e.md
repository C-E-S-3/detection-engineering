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
- `serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData` (Aura method for retrieving backend object configuration data)
- `serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems` (Aura method for retrieving object records with sorting and pagination)
- `serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews` (Aura method for identifying record lists)
- `serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData` (Aura method for retrieving home URLs)
- `apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled` (Aura method for checking self-registration status)
- `apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl` (Aura method for retrieving self-registration URL)

## 2. TTPs (MITRE ATT&CK Mapping)

- **Tactic:** Collection
  - **Technique ID:** T1530
  - **Technique Name:** Data from Cloud Storage Object
  - **Description:** Exploiting misconfigured access controls in Salesforce Aura framework to retrieve sensitive data such as credit card numbers, identity documents, and health information.

- **Tactic:** Discovery
  - **Technique ID:** T1087
  - **Technique Name:** Account Discovery
  - **Description:** Using the `getItems` Aura method to retrieve records for specific objects, including sensitive data, by exploiting misconfigured access controls.

- **Tactic:** Discovery
  - **Technique ID:** T1083
  - **Technique Name:** File and Directory Discovery
  - **Description:** Using the `getAppBootstrapData` Aura method to discover home URLs that may lead to administrative or configuration panels.

- **Tactic:** Credential Access
  - **Technique ID:** T1078
  - **Technique Name:** Valid Accounts
  - **Description:** Exploiting self-registration mechanisms to create authenticated accounts and gain unauthorized access to sensitive data.

## 3. Malware & Tools

### Tools
- **AuraInspector:** An open-source tool developed by Mandiant to identify and audit access control misconfigurations in Salesforce Aura framework.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor:** Not specified
- **Campaign Name:** Not specified
- **Motivations:** Exploitation of misconfigured Salesforce Aura endpoints to access sensitive data such as credit card numbers, identity documents, and health information.
- **Targeted Sectors/Geographies:** Organizations using Salesforce Experience Cloud, particularly those with misconfigured access controls.

## 5. Splunk Detection Searches

### Detecting Unauthorized Access to Aura Methods
```spl
index=proxy sourcetype=bluecoat | search uri_path="/serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData" OR uri_path="/serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems" OR uri_path="/serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews" OR uri_path="/serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData" OR uri_path="/apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled" OR uri_path="/apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl" | stats count by uri_path, src_ip
```
*This search identifies requests to known malicious or misconfigured Salesforce Aura methods.*

### Detecting Large Data Exfiltration via GraphQL
```spl
index=proxy sourcetype=bluecoat uri_path="/graphql" | stats count by src_ip, uri_query | where count > 2000
```
*This search identifies potential data exfiltration attempts using the GraphQL API to bypass Salesforce record limits.*

### Detecting Bulk Actions in Salesforce Aura
```spl
index=proxy sourcetype=bluecoat uri_path="/serviceComponent" | rex field=_raw "actions":\[(?<actions>.*?)\] | eval action_count=mvcount(actions) | where action_count > 100 | stats count by src_ip, action_count
```
*This search identifies bulk actions exceeding recommended limits, which could indicate abuse of the Salesforce Aura framework.*

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, to help organizations identify and remediate access control misconfigurations in Salesforce's Aura framework. These misconfigurations can expose sensitive data such as credit card numbers, identity documents, and health information. The report highlights several new techniques, including the use of GraphQL to bypass Salesforce's 2,000-record retrieval limit and the exploitation of misconfigured Aura methods to access sensitive data. Organizations using Salesforce Experience Cloud should immediately review their access control configurations and implement the recommended mitigations to prevent unauthorized data access.