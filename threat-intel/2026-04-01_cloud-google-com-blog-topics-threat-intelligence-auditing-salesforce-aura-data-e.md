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
  **Description**: The Salesforce Aura framework was found to have misconfigurations that allow unauthorized users to access sensitive data, such as credit card numbers, identity documents, and health information. Attackers can exploit these misconfigurations to retrieve records from Salesforce objects.

### Tactic: Discovery
- **Technique ID**: T1087.002
  **Technique Name**: Account Discovery: Domain Accounts
  **Description**: The AuraInspector tool can identify misconfigured access controls that expose sensitive data, including account records, to unauthorized users.

### Tactic: Collection
- **Technique ID**: T1530
  **Technique Name**: Data from Cloud Storage Object
  **Description**: The GraphQL API in Salesforce can be used to bypass the 2,000-record retrieval limit, allowing attackers to retrieve all records tied to a misconfigured object.

### Tactic: Defense Evasion
- **Technique ID**: T1070.004
  **Technique Name**: Indicator Removal on Host: File Deletion
  **Description**: The Salesforce Aura framework uses a mechanism called "boxcar'ing" to bundle multiple actions into a single request, minimizing network traffic and potentially evading detection.

## 3. Malware & Tools

### Tools
- **AuraInspector**: An open-source tool released by Mandiant to identify and audit access control misconfigurations in the Salesforce Aura framework.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor**: Not specified
- **Campaign Name**: Not specified
- **Motivations**: Exploitation of Salesforce Aura misconfigurations to access sensitive data such as credit card numbers, identity documents, and health information.
- **Targeted Sectors/Geographies**: Organizations using Salesforce Experience Cloud, potentially across various sectors.

## 5. Splunk Detection Searches

### Detecting Misconfigured Aura Endpoints
```spl
index=web proxy
| search uri_path="/aura" AND http_method=POST
| stats count by src_ip, uri_path, http_method
| where count > 100
| table src_ip, uri_path, count
```
*Comment: This search identifies IP addresses making excessive POST requests to the Salesforce Aura endpoint, which may indicate misuse or exploitation attempts.*

### Detecting GraphQL API Misuse
```spl
index=web proxy
| search uri_path="/graphql" AND http_method=POST
| stats count by src_ip, uri_path, http_method
| where count > 100
| table src_ip, uri_path, count
```
*Comment: This search identifies potential abuse of the GraphQL API for unauthorized data retrieval.*

### Detecting Bulk Actions in Salesforce Aura
```spl
index=web proxy
| search uri_path="/aura" AND http_method=POST
| rex field=_raw "Content-Length:\s(?<content_length>\d+)"
| where tonumber(content_length) > 100000
| stats count by src_ip, uri_path, content_length
```
*Comment: This search identifies bulk actions in Salesforce Aura that exceed recommended limits, which could indicate potential misuse.*

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, to help organizations identify and audit access control misconfigurations in the Salesforce Aura framework. These misconfigurations can expose sensitive data, such as credit card numbers and identity documents, to unauthorized users. Additionally, the Salesforce GraphQL API was found to allow attackers to bypass the 2,000-record retrieval limit, enabling the collection of large datasets from misconfigured objects. Organizations using Salesforce should immediately review their access control configurations and monitor for unusual activity on Aura and GraphQL endpoints.