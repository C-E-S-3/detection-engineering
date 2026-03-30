---
scraped_at: "2026-01-12T00:00:00Z"
source_url: "https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure/"
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### Domains/URLs
- No new domains or URLs identified.

### File Hashes
- No new file hashes identified.

### IP Addresses
- No new IP addresses identified.

### Other IOCs
- **Aura Method**: `serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData`
  - **Context**: Used to retrieve a list of objects in the backend Salesforce database.
- **Aura Method**: `serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems`
  - **Context**: Used to retrieve records for a specific object, with potential misuse to bypass Salesforce's 2,000-record retrieval limit using the `sortBy` parameter.
- **Aura Method**: `serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews`
  - **Context**: Used to identify if an object has an associated Record List component, which could be misconfigured to expose sensitive data.
- **Aura Method**: `serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData`
  - **Context**: Used to retrieve a list of Home URLs, which could expose administrative or configuration panels.
- **Aura Method**: `apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled`
  - **Context**: Used to check if self-registration is enabled.
- **Aura Method**: `apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl`
  - **Context**: Used to retrieve the self-registration URL.

## 2. TTPs (MITRE ATT&CK Mapping)

- **Tactic**: Initial Access
  - **Technique ID**: T1078.003 (Valid Accounts: Local Accounts)
    - **Description**: Exploiting misconfigured self-registration settings to gain unauthorized access to Salesforce instances.

- **Tactic**: Collection
  - **Technique ID**: T1213 (Data from Information Repositories)
    - **Description**: Exploiting misconfigured Salesforce Aura endpoints to retrieve sensitive data such as credit card numbers, identity documents, and health information.

- **Tactic**: Discovery
  - **Technique ID**: T1087.002 (Account Discovery: Domain Accounts)
    - **Description**: Using Aura methods to enumerate accessible objects and records, including sensitive data.

## 3. Malware & Tools

- **Tool**: AuraInspector
  - **Description**: An open-source command-line tool released by Mandiant to identify and audit access control misconfigurations in Salesforce Aura.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor**: Not specified.
- **Campaign**: Not specified.
- **Motivation**: Likely financial gain or data theft, targeting misconfigured Salesforce Aura endpoints to access sensitive data such as credit card numbers, identity documents, and health information.
- **Targeted Sectors**: Organizations using Salesforce Experience Cloud, particularly those managing sensitive customer data.

## 5. Splunk Detection Searches

### Detecting Misuse of Aura Methods

#### Search for `getConfigData` Aura Method Usage
```spl
index=proxy_logs
| search uri_path="/serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData"
| stats count by src_ip, user_agent
| sort - count
```
*Comment: This search identifies requests to the `getConfigData` Aura method, which could indicate attempts to enumerate backend Salesforce objects.*

#### Detecting Excessive `getItems` Requests with `sortBy` Parameter
```spl
index=proxy_logs
| search uri_path="/serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems" "sortBy="
| stats count by src_ip, user_agent
| where count > 100
| sort - count
```
*Comment: This search identifies potential abuse of the `getItems` Aura method to bypass Salesforce's 2,000-record retrieval limit.*

#### Detecting Access to Home URLs
```spl
index=proxy_logs
| search uri_path="/serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData"
| stats count by src_ip, user_agent
| sort - count
```
*Comment: This search identifies attempts to retrieve Home URLs, which could expose administrative or configuration panels.*

#### Detecting Self-Registration Enumeration
```spl
index=proxy_logs
| search uri_path="/apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled" OR uri_path="/apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl"
| stats count by src_ip, user_agent
| sort - count
```
*Comment: This search identifies attempts to enumerate self-registration settings and URLs.*

## 6. Executive Summary

On January 12, 2026, Mandiant released a detailed report and an open-source tool, AuraInspector, to help organizations identify and remediate access control misconfigurations in Salesforce's Aura framework. These misconfigurations can expose sensitive data, such as credit card numbers and identity documents, to unauthorized users. The report highlights novel techniques, including the use of GraphQL to bypass Salesforce's 2,000-record retrieval limit and the exploitation of misconfigured Aura methods to access sensitive data. Organizations using Salesforce Experience Cloud should immediately review their access control configurations and monitor for suspicious activity targeting Aura endpoints. Recommended actions include deploying the AuraInspector tool, auditing access control settings, and implementing Splunk detection searches provided in this report.