---
scraped_at: "2026-01-12T00:00:00Z"
source_url: "https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure/"
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### Domains/URLs
- None identified

### IP Addresses
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

### Tactic: Initial Access
- **Technique ID**: T1078 (Valid Accounts)
  - **Description**: Exploitation of misconfigured Salesforce access controls to gain unauthorized access to sensitive data, including credit card numbers, identity documents, and health information.

### Tactic: Collection
- **Technique ID**: T1530 (Data from Cloud Storage Object)
  - **Description**: Exploitation of Salesforce Aura framework misconfigurations to retrieve sensitive data using legitimate methods such as `getConfigData`, `getItems`, and GraphQL queries.

### Tactic: Discovery
- **Technique ID**: T1087 (Account Discovery)
  - **Description**: Use of Salesforce Aura methods to enumerate objects and their associated records, including the use of `getInitialListViews` to identify accessible record lists.

### Tactic: Exfiltration
- **Technique ID**: T1020 (Automated Exfiltration)
  - **Description**: Use of Salesforce Aura's "boxcar'ing" mechanism to bundle multiple actions into a single request, optimizing data exfiltration.

## 3. Malware & Tools
- **Tool**: AuraInspector
  - **Description**: An open-source command-line tool released by Mandiant to identify and audit access control misconfigurations in Salesforce Aura framework.

## 4. Threat Actor / Campaign Attribution
- **Threat Actor**: Not explicitly attributed to a specific group.
- **Campaign Name**: Not specified.
- **Motivations**: Likely financial gain through unauthorized access to sensitive data such as credit card numbers, identity documents, and health information.
- **Targeted Sectors/Geographies**: Organizations using Salesforce Experience Cloud.

## 5. Splunk Detection Searches

### Detecting Unauthorized Access to Salesforce Aura Endpoints
```spl
index=proxy OR index=web
| search uri_path="/aura" OR uri_path="/s/recordlist/*"
| stats count by src_ip, uri_path, http_user_agent
| where count > 100
| table src_ip, uri_path, http_user_agent, count
```
*This search identifies IP addresses making excessive requests to Salesforce Aura endpoints, which may indicate unauthorized access attempts.*

### Detecting GraphQL Queries to Salesforce Aura Controller
```spl
index=proxy OR index=web
| search uri_path="/graphql" AND http_method="POST"
| table _time, src_ip, uri_path, http_user_agent, http_request_body
```
*This search identifies GraphQL queries to Salesforce Aura controllers, which may indicate attempts to exploit misconfigurations.*

### Detecting Bulk Action Requests (Boxcar'ing)
```spl
index=proxy OR index=web
| search uri_path="/aura" AND http_method="POST"
| rex field=http_request_body "actions":\[(?<actions>.*?)\]
| eval action_count=mvcount(split(actions, "{"))
| where action_count > 100
| table _time, src_ip, uri_path, http_user_agent, action_count
```
*This search detects bulk action requests exceeding 100 actions, which may indicate attempts to exploit Salesforce Aura's boxcar'ing mechanism.*

### Detecting Self-Registration Enumeration
```spl
index=proxy OR index=web
| search uri_path="/applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled" OR uri_path="/applauncher.LoginFormController/ACTION$getSelfRegistrationUrl"
| stats count by src_ip, uri_path, http_user_agent
| table src_ip, uri_path, http_user_agent, count
```
*This search identifies attempts to enumerate self-registration status and URLs in Salesforce instances.*

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, to identify and audit access control misconfigurations in the Salesforce Aura framework. These misconfigurations can allow unauthorized access to sensitive data, including credit card numbers and identity documents. The report highlights several techniques, including the use of GraphQL to bypass Salesforce's 2,000-record retrieval limit, exploitation of misconfigured Aura methods, and the use of bulk action requests (boxcar'ing) to optimize data exfiltration. Organizations using Salesforce Experience Cloud should immediately audit their access control configurations, disable self-registration if not required, and monitor for excessive or anomalous requests to Salesforce Aura endpoints.