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
- **Technique ID**: T1530
  **Technique Name**: Data from Cloud Storage Object
  **Description**: The Salesforce Aura framework's misconfigurations allow unauthorized access to sensitive data, such as credit card numbers, identity documents, and health information.

### Tactic: Discovery
- **Technique ID**: T1087.002
  **Technique Name**: Account Discovery: Domain Accounts
  **Description**: Misconfigured access controls in Salesforce Aura allow attackers to retrieve records of user accounts, including sensitive information.

### Tactic: Collection
- **Technique ID**: T1530
  **Technique Name**: Data from Cloud Storage Object
  **Description**: Exploitation of the GraphQL API to bypass Salesforce's 2,000-record retrieval limit, enabling attackers to retrieve all records tied to an object in cases of misconfiguration.

### Tactic: Credential Access
- **Technique ID**: T1552.003
  **Technique Name**: Credentials from Web Browsers
  **Description**: Misconfigured Salesforce self-registration settings can allow attackers to create unauthorized accounts, potentially gaining access to sensitive data.

## 3. Malware & Tools

### Tools
- **AuraInspector**: An open-source command-line tool developed by Mandiant to identify and audit access control misconfigurations in Salesforce Aura.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor**: None explicitly identified.
- **Campaign Name**: None explicitly identified.
- **Motivations**: Likely financial gain or espionage, as the misconfigurations allow access to sensitive data such as credit card numbers, identity documents, and health information.
- **Targeted Sectors/Geographies**: Organizations using Salesforce, particularly those leveraging the Salesforce Experience Cloud.

## 5. Splunk Detection Searches

### Detecting Misuse of Aura Methods
```spl
index=web proxy
| search uri_path="/aura" AND http_method="POST"
| spath input=_raw path="actions{}.descriptor" output=descriptor
| search descriptor IN ("serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData", "serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems", "serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews", "serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData")
| stats count by src_ip, uri_path, descriptor
```
*Comment*: This search identifies potential misuse of Salesforce Aura methods by analyzing POST requests to the `/aura` endpoint and extracting the `descriptor` field.

### Detecting GraphQL API Usage
```spl
index=web proxy
| search uri_path="/graphql" AND http_method="POST"
| spath input=_raw path="query" output=query
| stats count by src_ip, uri_path, query
```
*Comment*: This search identifies potential abuse of the Salesforce GraphQL API by analyzing POST requests to the `/graphql` endpoint.

### Detecting Self-Registration Abuse
```spl
index=web proxy
| search uri_path="/applauncher.LoginFormController/ACTION$getSelfRegistrationUrl" OR uri_path="/applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled"
| stats count by src_ip, uri_path
```
*Comment*: This search identifies attempts to query self-registration status or retrieve self-registration URLs in Salesforce.

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, to identify and audit access control misconfigurations in the Salesforce Aura framework. These misconfigurations can expose sensitive data, including credit card numbers and identity documents, to unauthorized users. Additionally, attackers can exploit the GraphQL API to bypass Salesforce's 2,000-record retrieval limit, enabling the collection of large datasets in cases of misconfiguration. Organizations using Salesforce, particularly those leveraging the Experience Cloud, should immediately audit their access controls and implement the recommended mitigations to secure their environments.