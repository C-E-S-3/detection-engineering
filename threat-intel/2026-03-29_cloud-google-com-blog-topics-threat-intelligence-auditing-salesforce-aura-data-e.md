---
scraped_at: "2026-01-12T00:00:00Z"
source_url: "https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure/"
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### IP Addresses
- None identified

### Domains/URLs
- None identified

### File Hashes
- None identified

### Email Addresses
- None identified

### File Names/Paths
- None identified

### Registry Keys
- None identified

### Mutex Names
- None identified

### C2 Infrastructure
- None identified

## 2. TTPs (MITRE ATT&CK Mapping)

### Tactics and Techniques

- **Tactic: Collection (TA0009)**
  - **Technique: Data from Information Repositories (T1213)**
    - **Sub-technique: Data from Local System (T1213.001)**
      - **Description:** Exploiting misconfigured Salesforce Aura endpoints to retrieve sensitive data such as credit card numbers, identity documents, and health information.

- **Tactic: Initial Access (TA0001)**
  - **Technique: Exploit Public-Facing Application (T1190)**
    - **Description:** Exploiting misconfigured Salesforce Aura endpoints to gain unauthorized access to sensitive data.

- **Tactic: Discovery (TA0007)**
  - **Technique: Application Window Discovery (T1010)**
    - **Description:** Using Salesforce Aura methods to identify accessible objects and their associated data.

- **Tactic: Credential Access (TA0006)**
  - **Technique: Account Discovery (T1087)**
    - **Description:** Leveraging the `getIsSelfRegistrationEnabled` and `getSelfRegistrationUrl` Aura methods to identify self-registration pages and potentially gain unauthorized access.

## 3. Malware & Tools

- **Tool:** AuraInspector
  - **Description:** An open-source command-line tool released by Mandiant to identify and audit access control misconfigurations in Salesforce Aura.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor:** Not explicitly attributed to a specific group.
- **Campaign:** Not specified.
- **Motivations:** Likely financial gain or data theft, targeting organizations using Salesforce Experience Cloud.
- **Targeted Sectors/Geographies:** Organizations leveraging Salesforce Experience Cloud, potentially across various industries.

## 5. Splunk Detection Searches

### Detecting Misconfigured Aura Endpoints
```spl
index=proxy OR index=web
| search uri_path="/aura" AND http_method="POST"
| spath input=_raw output=actions path="actions{}"
| mvexpand actions
| spath input=actions output=descriptor path="descriptor"
| search descriptor IN ("serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData", "serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems", "serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews", "serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData")
| table _time, src_ip, uri_path, descriptor, actions
```
*This search identifies potentially misconfigured Salesforce Aura endpoints being accessed via HTTP POST requests. It extracts the `descriptor` field from the `actions` array in the request payload to identify specific methods being invoked.*

### Detecting Self-Registration Page Access
```spl
index=proxy OR index=web
| search uri_path="/applauncher.LoginFormController/ACTION$getSelfRegistrationUrl" OR uri_path="/applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled"
| table _time, src_ip, uri_path, http_user_agent
```
*This search identifies attempts to access Salesforce self-registration pages using the `getSelfRegistrationUrl` and `getIsSelfRegistrationEnabled` methods.*

### Detecting GraphQL API Usage
```spl
index=proxy OR index=web
| search uri_path="/graphql" AND http_method="POST"
| spath input=_raw output=query path="query"
| table _time, src_ip, uri_path, query
```
*This search identifies usage of the Salesforce GraphQL API, which could be used to retrieve large amounts of data from misconfigured objects.*

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, to help organizations identify and remediate access control misconfigurations in Salesforce Aura. These misconfigurations can expose sensitive data such as credit card numbers and identity documents. The report highlights new techniques, including the use of GraphQL to bypass Salesforce's 2,000-record retrieval limit and the exploitation of misconfigured Aura endpoints to access sensitive data. Organizations using Salesforce Experience Cloud should immediately audit their configurations, disable self-registration if not required, and monitor for unauthorized access to Aura endpoints and GraphQL APIs.