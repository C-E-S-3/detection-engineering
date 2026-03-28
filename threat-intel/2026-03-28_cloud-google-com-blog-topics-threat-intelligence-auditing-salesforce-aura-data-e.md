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
  **Technique Name**: Data from Cloud Storage Object
  **Description**: Misconfigured Salesforce Aura endpoints can allow unauthorized access to sensitive data, such as credit card numbers, identity documents, and health information, through methods like `getConfigData` and `getItems`.

### Tactic: Discovery (TA0007)
- **Technique ID**: T1087.002
  **Technique Name**: Account Discovery: Domain Accounts
  **Description**: Misconfigured Aura methods, such as `getInitialListViews`, can reveal record lists and associated objects, potentially exposing sensitive information.

### Tactic: Collection (TA0009)
- **Technique ID**: T1213.002
  **Technique Name**: Data from Information Repositories: SharePoint
  **Description**: The GraphQL Aura controller can be exploited to bypass Salesforce's 2,000-record retrieval limit, allowing attackers to retrieve all records tied to an object in misconfigured environments.

## 3. Malware & Tools

### Tools
- **AuraInspector**: An open-source tool released by Mandiant to identify and audit access control misconfigurations in the Salesforce Aura framework.

## 4. Threat Actor / Campaign Attribution
- **Threat Actor**: Not specified
- **Campaign Name**: Not specified
- **Motivations**: Exploitation of Salesforce Aura framework misconfigurations to access sensitive data, including credit card numbers, identity documents, and health information.
- **Targeted Sectors/Geographies**: Organizations using Salesforce Experience Cloud, particularly those with misconfigured access controls.

## 5. Splunk Detection Searches

### Detection for Misconfigured Aura Endpoints
```spl
index=web proxy
| search uri_path="/aura" AND http_method=POST
| spath input=_raw path=actions{} output=actions
| mvexpand actions
| spath input=actions path=descriptor output=descriptor
| search descriptor IN ("serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData", "serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems")
| table _time, src_ip, uri_path, descriptor, http_user_agent
```
*Comment*: Detects POST requests to Salesforce Aura endpoints with potentially misconfigured methods.

### Detection for GraphQL Aura Controller Abuse
```spl
index=web proxy
| search uri_path="/graphql" AND http_method=POST
| spath input=_raw path=actions{} output=actions
| mvexpand actions
| spath input=actions path=descriptor output=descriptor
| search descriptor="serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData"
| table _time, src_ip, uri_path, descriptor, http_user_agent
```
*Comment*: Identifies potential abuse of the GraphQL Aura controller to retrieve sensitive data.

### Detection for Self-Registration Enumeration
```spl
index=web proxy
| search uri_path="/applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled" OR uri_path="/applauncher.LoginFormController/ACTION$getSelfRegistrationUrl"
| table _time, src_ip, uri_path, http_user_agent
```
*Comment*: Detects attempts to enumerate self-registration status and URLs using Salesforce Aura methods.

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, to identify and audit access control misconfigurations within the Salesforce Aura framework. These misconfigurations can allow unauthorized access to sensitive data, such as credit card numbers and identity documents. Key techniques include exploiting misconfigured Aura methods (`getConfigData`, `getItems`) and abusing the GraphQL Aura controller to bypass Salesforce's 2,000-record retrieval limit. Organizations using Salesforce Experience Cloud should immediately assess their configurations for potential vulnerabilities and implement the recommended mitigations to prevent unauthorized data access.