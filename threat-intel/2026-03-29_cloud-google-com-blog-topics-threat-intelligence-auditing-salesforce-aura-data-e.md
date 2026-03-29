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
- `serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData` (Aura method for retrieving backend Salesforce database objects)
- `serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems` (Aura method for retrieving object records with sorting and pagination capabilities)
- `serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews` (Aura method for identifying associated Record List components)
- `serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData` (Aura method for retrieving administrative Home URLs)
- `apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled` (Aura method for checking self-registration status)
- `apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl` (Aura method for retrieving self-registration URL)

## 2. TTPs (MITRE ATT&CK Mapping)

- **Tactic**: Initial Access
  - **Technique ID**: T1078.003 (Valid Accounts: Cloud Accounts)
  - **Description**: Exploiting misconfigured Salesforce access controls to gain unauthorized access to sensitive data.

- **Tactic**: Discovery
  - **Technique ID**: T1087 (Account Discovery)
  - **Description**: Using Salesforce Aura methods to enumerate accessible objects, records, and associated metadata.

- **Tactic**: Collection
  - **Technique ID**: T1213 (Data from Information Repositories)
  - **Description**: Leveraging GraphQL and Aura methods to retrieve large volumes of records from Salesforce objects.

- **Tactic**: Defense Evasion
  - **Technique ID**: T1070.004 (Indicator Removal on Host: File Deletion)
  - **Description**: Using Salesforce's "boxcar'ing" mechanism to bundle multiple actions into a single request, potentially obfuscating malicious activity.

## 3. Malware & Tools

- **AuraInspector**: An open-source tool released by Mandiant to identify and audit access control misconfigurations in Salesforce Aura.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor**: Not specified
- **Campaign Name**: Not specified
- **Motivations**: Exploitation of Salesforce misconfigurations to gain unauthorized access to sensitive data, including credit card numbers, identity documents, and health information.
- **Targeted Sectors/Geographies**: Organizations using Salesforce Experience Cloud, particularly those with misconfigured access controls.

## 5. Splunk Detection Searches

### Detecting Unauthorized Access to Aura Methods

```spl
index=proxy sourcetype=bluecoat
| search uri_path="/serviceComponent" AND (uri_query="*ACTION$getConfigData*" OR uri_query="*ACTION$getItems*" OR uri_query="*ACTION$getInitialListViews*" OR uri_query="*ACTION$getAppBootstrapData*" OR uri_query="*ACTION$getIsSelfRegistrationEnabled*" OR uri_query="*ACTION$getSelfRegistrationUrl*")
| stats count by uri_path, uri_query, src_ip
| table uri_path, uri_query, src_ip, count
```
*Comment*: This search identifies suspicious access to Salesforce Aura methods that could indicate exploitation of misconfigurations.

### Detecting Bulked Actions in Salesforce Aura Requests

```spl
index=proxy sourcetype=bluecoat
| search uri_path="/serviceComponent" AND http_method="POST"
| rex field=_raw "\"actions\":\[(?<actions>.*?)\]"
| eval action_count=mvcount(split(actions, "},"))
| where action_count > 100
| stats count by src_ip, action_count
| table src_ip, action_count, count
```
*Comment*: This search detects Salesforce Aura requests that bundle more than 100 actions, which could indicate abuse of the "boxcar'ing" mechanism.

### Detecting GraphQL Queries to Salesforce

```spl
index=proxy sourcetype=bluecoat
| search uri_path="/graphql" AND http_method="POST"
| stats count by src_ip, uri_path, http_method
| table src_ip, uri_path, http_method, count
```
*Comment*: This search identifies GraphQL queries to Salesforce endpoints, which could be used to bypass record retrieval limits.

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, to help organizations identify and mitigate access control misconfigurations in Salesforce's Aura framework. The report highlights several previously undocumented techniques, including the use of GraphQL to bypass Salesforce's 2,000-record retrieval limit and the exploitation of misconfigured Aura methods to access sensitive data. Organizations using Salesforce Experience Cloud should immediately review their access control configurations, disable self-registration if not required, and monitor for unauthorized access to sensitive endpoints using the provided Splunk detection searches.