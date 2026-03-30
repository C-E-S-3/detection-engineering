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
- `serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData`: Used to retrieve a list of objects from the backend Salesforce database.
- `serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems`: Used to retrieve records for a specific object.
- `serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews`: Used to check if an object has an associated record list component.
- `serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData`: Used to retrieve home URLs, which may lead to administrative or configuration panels.
- `apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled`: Used to check if self-registration is enabled.
- `apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl`: Used to retrieve the self-registration URL.

## 2. TTPs (MITRE ATT&CK Mapping)

- **Tactic: Initial Access**
  - **Technique ID: T1078.003** - Valid Accounts: Cloud Accounts
    - Exploitation of misconfigured Salesforce Aura endpoints to gain unauthorized access to sensitive data.

- **Tactic: Discovery**
  - **Technique ID: T1087.002** - Account Discovery: Domain Accounts
    - Using Aura methods to retrieve user account information and associated records.

- **Tactic: Collection**
  - **Technique ID: T1213.002** - Data from Information Repositories: Sharepoint
    - Exploiting misconfigured Salesforce Aura endpoints to retrieve sensitive records from Salesforce objects.

- **Tactic: Exfiltration**
  - **Technique ID: T1020** - Automated Exfiltration
    - Using the GraphQL API to bypass Salesforce's 2,000-record retrieval limit and exfiltrate large amounts of data.

## 3. Malware & Tools

- **AuraInspector**: An open-source tool developed by Mandiant to identify and audit access control misconfigurations in Salesforce Aura.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor**: Not specified.
- **Campaign**: Not specified.
- **Motivations**: Exploitation of misconfigured Salesforce Aura endpoints to gain unauthorized access to sensitive data such as credit card numbers, identity documents, and health information.
- **Targeted Sectors/Geographies**: Organizations using Salesforce Experience Cloud.

## 5. Splunk Detection Searches

### Detecting Unauthorized Access to Aura Endpoints
```spl
index=proxy_logs
| search uri_path="/aura" AND http_method="POST"
| spath input=_raw output=actions path="actions{}"
| mvexpand actions
| spath input=actions output=descriptor path="descriptor"
| search descriptor IN ("serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData", "serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems", "serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews", "serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData", "apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled", "apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl")
| stats count by src_ip, uri_path, descriptor
```
*This search identifies unauthorized access attempts to Salesforce Aura endpoints by analyzing proxy logs for specific Aura method descriptors.*

### Detecting GraphQL API Usage for Data Exfiltration
```spl
index=proxy_logs
| search uri_path="/graphql" AND http_method="POST"
| spath input=_raw output=query path="query"
| search query="*"
| stats count by src_ip, uri_path, query
```
*This search identifies potential abuse of the GraphQL API for data exfiltration by analyzing POST requests to the `/graphql` endpoint.*

### Detecting Bulk Actions in Salesforce Aura
```spl
index=proxy_logs
| search uri_path="/aura" AND http_method="POST"
| spath input=_raw output=actions path="actions{}"
| eval action_count=mvcount(actions)
| where action_count > 100
| stats count by src_ip, uri_path, action_count
```
*This search identifies bulked Aura actions exceeding the recommended limit of 100 actions per request.*

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, to help identify and audit access control misconfigurations in Salesforce Aura. The report highlights several techniques, including the use of GraphQL APIs and Aura methods, to exploit misconfigurations and retrieve sensitive data. These techniques can bypass Salesforce's record retrieval limits and expose sensitive information if access controls are not properly configured. Organizations using Salesforce Experience Cloud should urgently review their access control configurations and implement the recommended mitigations to prevent unauthorized data access.