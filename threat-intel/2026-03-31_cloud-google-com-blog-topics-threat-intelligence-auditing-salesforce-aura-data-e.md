---
scraped_at: 2026-01-12T00:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure/
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

### Tactic: Initial Access
- **Technique ID**: T1190 (Exploit Public-Facing Application)
  - **Description**: Misconfigured Salesforce Aura endpoints can allow unauthorized access to sensitive data, including credit card numbers and identity documents.

### Tactic: Collection
- **Technique ID**: T1213 (Data from Information Repositories)
  - **Description**: Exploitation of misconfigured Aura methods (e.g., `getConfigData`, `getItems`) to retrieve sensitive records from Salesforce databases.

### Tactic: Discovery
- **Technique ID**: T1087.002 (Account Discovery: Domain Accounts)
  - **Description**: Using the `getInitialListViews` Aura method to identify accessible record lists and associated objects.

### Tactic: Exfiltration
- **Technique ID**: T1041 (Exfiltration Over C2 Channel)
  - **Description**: Leveraging GraphQL APIs to exfiltrate large volumes of data from misconfigured Salesforce objects.

## 3. Malware & Tools

### Tools
- **AuraInspector**: An open-source tool developed by Mandiant to identify and audit access control misconfigurations in Salesforce Aura.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor**: Not explicitly mentioned.
- **Campaign Name**: Not explicitly mentioned.
- **Motivations**: Likely financial gain through unauthorized access to sensitive data such as credit card numbers, identity documents, and health information.
- **Targeted Sectors**: Organizations using Salesforce Experience Cloud, particularly those with misconfigured access controls.

## 5. Splunk Detection Searches

### Detecting Misconfigured Aura Endpoints
```spl
index=web proxy
| search uri_path="/aura" AND http_method=POST
| stats count by uri_path, http_method, src_ip
| where count > 100
| table uri_path, http_method, src_ip, count
```
*Comment: Identifies potentially misconfigured Salesforce Aura endpoints being accessed via POST requests.*

### Detecting GraphQL API Abuse
```spl
index=web proxy
| search uri_path="/graphql" AND http_method=POST
| stats count by uri_path, http_method, src_ip
| where count > 100
| table uri_path, http_method, src_ip, count
```
*Comment: Detects high-frequency access to the GraphQL API endpoint, which could indicate data exfiltration attempts.*

### Detecting Bulk Actions in Salesforce Aura
```spl
index=web proxy
| search uri_path="/aura" AND http_method=POST AND request_body="actions"
| rex field=request_body "\"actions\":\[(?<actions>.*?)\]"
| eval action_count=mvcount(split(actions, ","))
| where action_count > 100
| table src_ip, uri_path, action_count
```
*Comment: Identifies bulk actions in Salesforce Aura requests exceeding 100 actions per request.*

### Detecting Self-Registration Abuse
```spl
index=web proxy
| search uri_path="/applauncher.LoginFormController/ACTION$getSelfRegistrationUrl" OR uri_path="/applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled"
| stats count by src_ip, uri_path
| table src_ip, uri_path, count
```
*Comment: Detects attempts to query self-registration status and URLs, which could indicate reconnaissance activity.*

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, to identify and audit access control misconfigurations in Salesforce Aura, a framework used in Salesforce applications. The report highlights several techniques that attackers could exploit, including misconfigured Aura endpoints, GraphQL APIs, and self-registration pages, to gain unauthorized access to sensitive data. Organizations using Salesforce Experience Cloud should immediately review their access control configurations, disable unnecessary self-registration, and monitor for suspicious activity on Salesforce-related endpoints.