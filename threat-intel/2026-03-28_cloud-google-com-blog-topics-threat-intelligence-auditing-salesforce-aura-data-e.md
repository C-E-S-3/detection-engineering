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
- `serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData` - Aura method used to retrieve backend Salesforce database object configuration data.
- `serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems` - Aura method used to retrieve records for a specific object.
- `serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews` - Aura method used to check if an object has an associated record list component.
- `serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData` - Aura method used to retrieve home URLs for administration or configuration panels.
- `apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled` - Aura method used to check if self-registration is enabled.
- `apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl` - Aura method used to retrieve the self-registration URL.

## 2. TTPs (MITRE ATT&CK Mapping)

- **T1190 - Exploit Public-Facing Application**: Exploiting misconfigured Salesforce Aura endpoints to access sensitive data.
- **T1210 - Exploitation of Remote Services**: Using GraphQL API to bypass record retrieval limits and access large datasets.
- **T1078 - Valid Accounts**: Exploiting self-registration mechanisms to gain unauthorized access.
- **T1081 - Credentials in Files**: Identifying misconfigured administration or configuration panels via home URLs.

## 3. Malware & Tools

- **AuraInspector**: An open-source tool developed by Mandiant to identify and audit access control misconfigurations in Salesforce Aura.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor**: Not explicitly attributed to a specific threat actor.
- **Campaign Name**: Not specified.
- **Motivations**: Likely financial gain or data theft, targeting sensitive data such as credit card numbers, identity documents, and health information.
- **Targeted Sectors/Geographies**: Organizations using Salesforce Experience Cloud, potentially across various industries.

## 5. Splunk Detection Searches

### Detecting Unauthorized Access to Aura Methods
```spl
index=proxy_logs
| search uri_path="/serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData"
| stats count by src_ip, user, uri_path
| where count > 10
```
*Comment: This search detects multiple requests to the `getConfigData` Aura method, which could indicate potential misuse.*

### Detecting GraphQL API Abuse
```spl
index=proxy_logs
| search uri_path="/graphql" method="POST"
| stats count by src_ip, user, uri_path
| where count > 10
```
*Comment: This search identifies excessive use of the GraphQL API, which may indicate attempts to bypass record retrieval limits.*

### Detecting Self-Registration Abuse
```spl
index=web_logs
| search uri_path="/self-registration"
| stats count by src_ip, user, uri_path
| where count > 5
```
*Comment: This search detects repeated access to self-registration pages, which could indicate abuse of the self-registration mechanism.*

### Detecting Access to Administration or Configuration Panels
```spl
index=proxy_logs
| search uri_path="/CMCAppController/ACTION$getAppBootstrapData"
| stats count by src_ip, user, uri_path
| where count > 5
```
*Comment: This search identifies access to administration or configuration panels via home URLs.*

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, to help organizations identify and audit access control misconfigurations in Salesforce's Aura framework. The report highlights several new techniques, including the exploitation of Aura methods and the GraphQL API to bypass record retrieval limits and access sensitive data. Additionally, it identifies risks associated with misconfigured self-registration mechanisms and administration panels. Organizations using Salesforce Experience Cloud should immediately review their access control configurations, disable unnecessary self-registration, and monitor for suspicious activity targeting Aura endpoints and GraphQL APIs.