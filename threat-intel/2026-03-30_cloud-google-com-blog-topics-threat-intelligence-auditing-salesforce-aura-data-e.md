---
scraped_at: "2026-01-12T00:00:00Z"
source_url: "https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure/"
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
- `serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData`: Used to retrieve backend Salesforce database object configurations.
- `serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems`: Used to retrieve records for specific objects.
- `serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews`: Used to check if an object has an associated record list component.
- `serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData`: Used to retrieve home URLs for administration or configuration panels.
- `apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled`: Used to check if self-registration is enabled.
- `apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl`: Used to retrieve the self-registration URL.

## 2. TTPs (MITRE ATT&CK Mapping)

- **Tactic: Initial Access**
  - **Technique ID: T1078.003 (Valid Accounts: Cloud Accounts)**
    - **Description:** Exploiting misconfigured Salesforce Aura endpoints to gain unauthorized access to sensitive data.

- **Tactic: Discovery**
  - **Technique ID: T1087 (Account Discovery)**
    - **Description:** Using Aura methods to retrieve user account information and associated records.

- **Tactic: Collection**
  - **Technique ID: T1213 (Data from Information Repositories)**
    - **Description:** Leveraging GraphQL API to bypass Salesforce's 2,000-record retrieval limit and access sensitive data.

- **Tactic: Credential Access**
  - **Technique ID: T1552.001 (Unsecured Credentials: Credentials In Files)**
    - **Description:** Identifying misconfigured access controls that expose sensitive data such as credit card numbers and identity documents.

## 3. Malware & Tools

- **AuraInspector**: An open-source tool released by Mandiant to identify and audit access control misconfigurations within the Salesforce Aura framework.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor:** Mandiant Offensive Security Services (OSS) identified these techniques during engagements. No specific threat actor or campaign attribution is provided in the source.
- **Targeted Sectors:** Organizations using Salesforce Experience Cloud, particularly those handling sensitive data such as credit card numbers, identity documents, and health information.

## 5. Splunk Detection Searches

### Detecting Unauthorized Access to Aura Endpoints
```spl
index=proxy_logs
| search uri_path="/aura" AND (uri_query="*getConfigData*" OR uri_query="*getItems*" OR uri_query="*getInitialListViews*" OR uri_query="*getAppBootstrapData*" OR uri_query="*getIsSelfRegistrationEnabled*" OR uri_query="*getSelfRegistrationUrl*")
| stats count by src_ip, uri_path, uri_query
| table src_ip, uri_path, uri_query, count
```
*Comment: This search identifies access to Salesforce Aura endpoints that may indicate unauthorized data retrieval attempts.*

### Detecting Bulk Actions in Salesforce Aura
```spl
index=proxy_logs
| search uri_path="/aura" AND uri_query="*actions*"
| rex field=uri_query "actions":\[(?<actions>.*?)\]
| eval action_count=mvcount(split(actions, "},"))
| where action_count > 100
| table src_ip, uri_path, action_count
```
*Comment: This search detects bulk actions exceeding the recommended limit of 100 actions per request.*

### Monitoring GraphQL API Usage
```spl
index=proxy_logs
| search uri_path="/graphql" AND method="POST"
| stats count by src_ip, uri_path, method
| table src_ip, uri_path, method, count
```
*Comment: This search identifies usage of the GraphQL API, which could be used to bypass Salesforce's record retrieval limits.*

### Detecting Self-Registration Page Access
```spl
index=proxy_logs
| search uri_path="/applauncher.LoginFormController" AND (uri_query="*getIsSelfRegistrationEnabled*" OR uri_query="*getSelfRegistrationUrl*")
| stats count by src_ip, uri_path, uri_query
| table src_ip, uri_path, uri_query, count
```
*Comment: This search identifies attempts to access self-registration-related methods in Salesforce.*

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, to help organizations identify and audit access control misconfigurations in Salesforce's Aura framework. The report highlights several previously undocumented techniques, including the use of GraphQL to bypass Salesforce's 2,000-record retrieval limit and the exploitation of misconfigured Aura endpoints to access sensitive data. Organizations using Salesforce Experience Cloud should immediately review their access control configurations, disable self-registration if not required, and monitor for unauthorized access to Salesforce endpoints using the provided Splunk detection searches.