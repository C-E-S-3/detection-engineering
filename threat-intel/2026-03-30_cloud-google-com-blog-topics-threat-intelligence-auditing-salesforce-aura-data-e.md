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
- `serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems` (Aura method for retrieving object records)
- `serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews` (Aura method for checking associated record list components)
- `serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData` (Aura method for retrieving home URLs)
- `apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled` (Aura method for checking self-registration status)
- `apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl` (Aura method for retrieving self-registration URL)

## 2. TTPs (MITRE ATT&CK Mapping)

### Tactic: Initial Access
- **T1190 - Exploit Public-Facing Application**: Exploiting misconfigured Salesforce Aura endpoints to access sensitive data such as credit card numbers, identity documents, and health information.

### Tactic: Discovery
- **T1592 - Gather Victim Host Information**: Using the `getConfigData` Aura method to retrieve backend Salesforce database objects.
- **T1592.002 - Network Share Discovery**: Using the `getInitialListViews` Aura method to identify associated record list components and accessible objects.

### Tactic: Collection
- **T1530 - Data from Cloud Storage Object**: Exploiting misconfigured Aura endpoints to retrieve sensitive records from Salesforce objects.
- **T1074.001 - Local Data Staging**: Using the `sortBy` parameter in Aura methods to bypass Salesforce's 2,000-record retrieval limit and collect additional records.

### Tactic: Credential Access
- **T1078 - Valid Accounts**: Exploiting misconfigured self-registration settings to create unauthorized accounts with elevated access.

## 3. Malware & Tools

### Tools
- **AuraInspector**: An open-source tool developed by Mandiant to identify and audit access control misconfigurations in Salesforce Aura framework.

## 4. Threat Actor / Campaign Attribution
- **Threat Actor**: Not specified
- **Campaign Name**: Not specified
- **Motivations**: Exploiting Salesforce Aura framework misconfigurations to gain unauthorized access to sensitive data, including credit card numbers, identity documents, and health information.
- **Targeted Sectors/Geographies**: Organizations using Salesforce Experience Cloud.

## 5. Splunk Detection Searches

### Detecting Unauthorized Access to Aura Methods
```spl
index=web_logs sourcetype=access_combined
| search "POST /aura" "serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData"
| stats count by src_ip, http_user_agent
| sort - count
```
*# This search identifies unauthorized access attempts to the `getConfigData` Aura method by analyzing web server logs.*

### Detecting Misuse of `getItems` Aura Method
```spl
index=web_logs sourcetype=access_combined
| search "POST /aura" "serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems"
| stats count by src_ip, http_user_agent
| sort - count
```
*# This search identifies potential misuse of the `getItems` Aura method for unauthorized data retrieval.*

### Detecting Access to Home URLs
```spl
index=web_logs sourcetype=access_combined
| search "POST /aura" "serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData"
| stats count by src_ip, http_user_agent
| sort - count
```
*# This search identifies attempts to retrieve home URLs using the `getAppBootstrapData` Aura method.*

### Detecting Self-Registration Abuse
```spl
index=web_logs sourcetype=access_combined
| search "POST /aura" "apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled" OR "apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl"
| stats count by src_ip, http_user_agent
| sort - count
```
*# This search identifies attempts to exploit self-registration misconfigurations in Salesforce instances.*

## 6. Executive Summary

On January 12, 2026, Mandiant released a detailed report on common access control misconfigurations in the Salesforce Aura framework, which could expose sensitive data such as credit card numbers, identity documents, and health information. The report introduces a new open-source tool, AuraInspector, designed to help administrators identify and remediate these vulnerabilities. Notably, the report highlights a previously undocumented technique using the GraphQL API to bypass Salesforce's 2,000-record retrieval limit, which could be exploited in cases of misconfigured access controls. Organizations using Salesforce Experience Cloud are advised to review their access control configurations, disable self-registration if not required, and monitor for unauthorized access to Aura methods and endpoints.