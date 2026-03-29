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
- **Technique ID:** T1213.003
  **Name:** Data from Information Repositories: Sharepoint
  **Description:** Misconfigured Salesforce Aura endpoints can be exploited to retrieve sensitive data such as credit card numbers, identity documents, and health information.

### Tactic: Collection (TA0009)
- **Technique ID:** T1530
  **Name:** Data from Cloud Storage Object
  **Description:** Exploiting Salesforce Aura misconfigurations to retrieve sensitive data stored in Salesforce objects.

### Tactic: Initial Access (TA0001)
- **Technique ID:** T1078.003
  **Name:** Valid Accounts: Cloud Accounts
  **Description:** Exploiting self-registration misconfigurations to gain unauthorized access to Salesforce instances.

### Tactic: Discovery (TA0007)
- **Technique ID:** T1087.004
  **Name:** Account Discovery: Cloud Account
  **Description:** Using Salesforce Aura methods to identify accessible objects and their associated record lists.

### Tactic: Credential Access (TA0006)
- **Technique ID:** T1552
  **Name:** Unsecured Credentials
  **Description:** Identifying and exploiting misconfigured Salesforce home URLs to access administrative or configuration panels.

## 3. Malware & Tools

### Tools
- **AuraInspector**: An open-source tool released by Mandiant to identify and audit access control misconfigurations in Salesforce Aura.

## 4. Threat Actor / Campaign Attribution
- **Threat Actor:** Not specified
- **Campaign Name:** Not specified
- **Motivations:** Exploitation of Salesforce Aura misconfigurations to gain unauthorized access to sensitive data, administrative panels, and other resources.
- **Targeted Sectors/Geographies:** Organizations using Salesforce Experience Cloud, potentially across various industries.

## 5. Splunk Detection Searches

### Detecting Misconfigured Aura Endpoints
```spl
index=proxy OR index=web
| search uri_path="*/serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData"
| stats count by src_ip, uri_path, http_user_agent
| sort - count
```
*This search identifies requests to the `getConfigData` Aura method, which could indicate attempts to exploit misconfigured endpoints.*

### Detecting GraphQL API Usage
```spl
index=proxy OR index=web
| search uri_path="*/graphql"
| stats count by src_ip, uri_path, http_user_agent
| sort - count
```
*This search identifies GraphQL API usage, which could be leveraged to bypass Salesforce's 2,000-record retrieval limit.*

### Detecting Self-Registration Exploitation
```spl
index=proxy OR index=web
| search uri_path="*/applauncher.LoginFormController/ACTION$getSelfRegistrationUrl"
| stats count by src_ip, uri_path, http_user_agent
| sort - count
```
*This search identifies attempts to access self-registration URLs, which could indicate exploitation of misconfigured self-registration settings.*

### Detecting Bulk Action Abuse
```spl
index=proxy OR index=web
| search uri_path="*/serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems"
| rex field=_raw "\"actions\":\[(?<actions>.*?)\]"
| eval action_count=mvcount(actions)
| where action_count > 100
| stats count by src_ip, uri_path, http_user_agent
| sort - count
```
*This search identifies bulk action requests with more than 100 actions, which could indicate attempts to exploit Salesforce's boxcar'ing mechanism.*

### Detecting Unauthorized Access to Home URLs
```spl
index=proxy OR index=web
| search uri_path="*/ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData"
| stats count by src_ip, uri_path, http_user_agent
| sort - count
```
*This search identifies attempts to retrieve home URLs, which could indicate reconnaissance for administrative or configuration panels.*

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, to help organizations identify and mitigate access control misconfigurations in the Salesforce Aura framework. These misconfigurations can expose sensitive data, such as credit card numbers and health information, to unauthorized users. The report highlights a previously undocumented technique using GraphQL to bypass Salesforce's 2,000-record retrieval limit, as well as methods to exploit misconfigured self-registration settings and access administrative panels via home URLs. Organizations using Salesforce should immediately review their access control configurations, disable self-registration if not required, and monitor for suspicious activity targeting Salesforce endpoints.