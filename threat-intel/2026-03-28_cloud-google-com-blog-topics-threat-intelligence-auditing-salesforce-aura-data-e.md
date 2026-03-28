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

### Tactics and Techniques
- **Tactic:** Collection (TA0009)
  - **Technique:** Data from Information Repositories (T1213)
    - **Description:** Exploiting Salesforce Aura misconfigurations to retrieve sensitive data such as credit card numbers, identity documents, and health information.

- **Tactic:** Discovery (TA0007)
  - **Technique:** Application Discovery (T1010)
    - **Description:** Using the `getInitialListViews` Aura method to identify accessible Record List components and their associated objects.

- **Tactic:** Collection (TA0009)
  - **Technique:** Automated Collection (T1119)
    - **Description:** Leveraging the AuraInspector tool to automate the detection of access control misconfigurations and data exposures.

- **Tactic:** Collection (TA0009)
  - **Technique:** Data from Local System (T1005)
    - **Description:** Using the GraphQL Aura controller to bypass Salesforce's 2,000-record retrieval limit and access additional records.

## 3. Malware & Tools

### Tools
- **AuraInspector**: An open-source command-line tool developed by Mandiant to identify and audit access control misconfigurations in Salesforce's Aura framework.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor:** Not explicitly attributed to a named group.
- **Campaign Name:** Not specified.
- **Motivations:** Likely financial or espionage-related, given the focus on accessing sensitive data such as credit card numbers, identity documents, and health information.
- **Targeted Sectors/Geographies:** Organizations using Salesforce Experience Cloud, potentially across multiple sectors.

## 5. Splunk Detection Searches

### Detecting Misuse of Aura Methods

#### Detecting `getConfigData` Method Usage
```spl
index=proxy OR index=web 
| search "serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData"
| stats count by src_ip, user, uri, http_method
| sort - count
```
*Comment: This search identifies requests to the `getConfigData` Aura method, which could indicate attempts to exploit access control misconfigurations.*

### Detecting GraphQL API Usage
```spl
index=proxy OR index=web 
| search "GraphQL" "User Interface API"
| stats count by src_ip, user, uri, http_method
| sort - count
```
*Comment: This search identifies GraphQL API usage, which could be leveraged to bypass Salesforce's 2,000-record retrieval limit.*

### Detecting Bulk Action Requests
```spl
index=proxy OR index=web 
| search "Content-Length" "actions" "serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems"
| stats count by src_ip, user, uri, http_method
| sort - count
```
*Comment: This search identifies bulk action requests that may indicate attempts to retrieve large amounts of data from Salesforce.*

### Detecting Self-Registration Enumeration
```spl
index=proxy OR index=web 
| search "apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled" OR "apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl"
| stats count by src_ip, user, uri, http_method
| sort - count
```
*Comment: This search identifies attempts to enumerate self-registration status and URLs, which could indicate reconnaissance activity.*

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, to identify and audit access control misconfigurations in Salesforce's Aura framework. These misconfigurations can expose sensitive data, such as credit card numbers and health information, to unauthorized users. Additionally, Mandiant has disclosed a previously undocumented technique using the GraphQL Aura controller to bypass Salesforce's 2,000-record retrieval limit, enabling attackers to access significantly larger datasets in case of misconfigurations. Organizations using Salesforce Experience Cloud should immediately review their access control configurations, disable unnecessary features like self-registration, and monitor for suspicious activity using the provided Splunk detection searches.
