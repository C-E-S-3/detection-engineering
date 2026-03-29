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
- **Aura Method**: `serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData` - Used to retrieve a list of objects in the backend Salesforce database.
- **Aura Method**: `serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems` - Used to retrieve records for a specific object.
- **Aura Method**: `serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews` - Used to check if an object has an associated record list component.
- **Aura Method**: `serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData` - Used to retrieve home URLs for administration or configuration panels.
- **Aura Method**: `apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled` - Used to check if self-registration is enabled.
- **Aura Method**: `apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl` - Used to retrieve the self-registration URL.

## 2. TTPs (MITRE ATT&CK Mapping)

- **Tactic**: Initial Access
  - **Technique**: Exploit Public-Facing Application (T1190)
    - **Description**: Exploiting misconfigured Salesforce Aura endpoints to gain unauthorized access to sensitive data such as credit card numbers, identity documents, and health information.

- **Tactic**: Collection
  - **Technique**: Automated Collection (T1119)
    - **Description**: Using the AuraInspector tool to automate the detection and collection of misconfigured access controls and sensitive data.

- **Tactic**: Discovery
  - **Technique**: Application Window Discovery (T1010)
    - **Description**: Leveraging Salesforce Aura methods to identify accessible Record Lists and home URLs for administrative or configuration panels.

- **Tactic**: Data from Information Repositories
  - **Technique**: Data from Information Repositories (T1213)
    - **Description**: Using the GraphQL API to bypass Salesforce's 2,000-record retrieval limit and access additional records in misconfigured objects.

## 3. Malware & Tools

- **Tool**: AuraInspector
  - **Description**: Open-source command-line tool released by Mandiant to identify and audit access control misconfigurations in the Salesforce Aura framework.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor**: None explicitly mentioned.
- **Campaign**: None explicitly mentioned.
- **Targeted Sectors/Geographies**: Organizations using Salesforce Experience Cloud, particularly those with misconfigured access controls.

## 5. Splunk Detection Searches

### Detecting Unauthorized Access to Aura Methods
```spl
index=web proxy
| search uri_path="/aura" AND (uri_query="*ACTION$getConfigData*" OR uri_query="*ACTION$getItems*" OR uri_query="*ACTION$getInitialListViews*" OR uri_query="*ACTION$getAppBootstrapData*" OR uri_query="*ACTION$getIsSelfRegistrationEnabled*" OR uri_query="*ACTION$getSelfRegistrationUrl*")
| stats count by uri_path, uri_query, src_ip
| table uri_path, uri_query, src_ip, count
```
*This search detects access to specific Salesforce Aura methods that may indicate attempts to exploit misconfigurations.*

### Detecting GraphQL API Usage for Data Exfiltration
```spl
index=web proxy
| search uri_path="/graphql" AND http_method="POST"
| rex field=_raw "query (?<graphql_query>\{.*\})"
| stats count by src_ip, graphql_query
| table src_ip, graphql_query, count
```
*This search identifies GraphQL API usage, which could indicate attempts to exploit misconfigured Salesforce objects.*

### Detecting Bulk Actions via Aura
```spl
index=web proxy
| search uri_path="/aura" AND http_method="POST"
| rex field=_raw "actions":\[(?<actions>.*?)\]
| eval action_count=mvcount(split(actions, "{"))
| where action_count > 100
| stats count by src_ip, action_count
| table src_ip, action_count, count
```
*This search identifies bulk actions in Salesforce Aura requests that exceed the recommended limit of 100 actions per request.*

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, to help organizations identify and audit access control misconfigurations in Salesforce's Aura framework. These misconfigurations can expose sensitive data, including credit card numbers and identity documents, to unauthorized users. The report highlights novel techniques, such as using GraphQL to bypass Salesforce's 2,000-record retrieval limit and leveraging specific Aura methods to access sensitive data and administrative panels. Organizations using Salesforce should immediately review their access control configurations, disable unnecessary self-registration, and monitor for unauthorized access to sensitive endpoints using the provided Splunk detection searches.