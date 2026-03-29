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
- None identified

## 2. TTPs (MITRE ATT&CK Mapping)

### Tactic: Collection (TA0009)
- **Technique ID**: T1530
  **Name**: Data from Cloud Storage Object
  **Description**: The Salesforce Aura framework was found to have misconfigurations that could allow unauthorized access to sensitive data such as credit card numbers, identity documents, and health information. Attackers can exploit these misconfigurations to retrieve data from Salesforce objects.

### Tactic: Discovery (TA0007)
- **Technique ID**: T1087.002
  **Name**: Account Discovery: Domain Accounts
  **Description**: The AuraInspector tool can identify misconfigured access controls that allow guest or unauthorized users to access Salesforce Account object records.

### Tactic: Collection (TA0009)
- **Technique ID**: T1530
  **Name**: Data from Cloud Storage Object
  **Description**: The GraphQL API in Salesforce can be exploited to bypass the 2,000-record retrieval limit, allowing attackers to retrieve all records tied to an object in cases of misconfiguration.

### Tactic: Discovery (TA0007)
- **Technique ID**: T1083
  **Name**: File and Directory Discovery
  **Description**: The `getAppBootstrapData` Aura method can be used to retrieve a list of home URLs, which may include administration or configuration panels for third-party modules installed on the Salesforce instance.

### Tactic: Initial Access (TA0001)
- **Technique ID**: T1078
  **Name**: Valid Accounts
  **Description**: The `getIsSelfRegistrationEnabled` and `getSelfRegistrationUrl` Aura methods can be used to identify whether self-registration is enabled and retrieve the self-registration URL, potentially allowing attackers to create authenticated accounts.

## 3. Malware & Tools

### Tools
- **AuraInspector**: An open-source command-line tool released by Mandiant to identify and audit access control misconfigurations in the Salesforce Aura framework.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor**: Not explicitly mentioned.
- **Campaign Name**: Not explicitly mentioned.
- **Motivations**: Likely to exploit misconfigurations in Salesforce Aura to access sensitive data such as credit card numbers, identity documents, and health information.
- **Targeted Sectors/Geographies**: Organizations using Salesforce Experience Cloud, potentially across various sectors.

## 5. Splunk Detection Searches

### Detecting Misconfigured Aura Endpoints
```spl
index=proxy_logs
| search uri_path="/aura" AND http_method="POST"
| spath input=_raw output=actions path="actions{}"
| mvexpand actions
| spath input=actions output=descriptor path="descriptor"
| search descriptor IN ("serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData", "serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems", "serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews", "serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData")
| table _time, src_ip, uri_path, descriptor, actions
```
*This search detects HTTP POST requests to Salesforce Aura endpoints with descriptors associated with potential misconfigurations.*

### Detecting GraphQL API Usage
```spl
index=proxy_logs
| search uri_path="/graphql" AND http_method="POST"
| spath input=_raw output=query path="query"
| table _time, src_ip, uri_path, query
```
*This search identifies GraphQL API usage, which could indicate attempts to exploit the API for unauthorized data access.*

### Identifying Self-Registration Activity
```spl
index=proxy_logs
| search uri_path="/applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled" OR uri_path="/applauncher.LoginFormController/ACTION$getSelfRegistrationUrl"
| table _time, src_ip, uri_path, http_method
```
*This search detects requests to Aura methods that expose self-registration status and URLs.*

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, to help organizations identify and mitigate access control misconfigurations in Salesforce's Aura framework. These misconfigurations can expose sensitive data, such as credit card numbers and health information, to unauthorized users. Additionally, attackers can exploit Salesforce's GraphQL API to bypass record retrieval limits, potentially accessing large datasets. Organizations using Salesforce should immediately audit their configurations, disable self-registration if not required, and monitor for suspicious activity targeting Aura endpoints and GraphQL APIs.