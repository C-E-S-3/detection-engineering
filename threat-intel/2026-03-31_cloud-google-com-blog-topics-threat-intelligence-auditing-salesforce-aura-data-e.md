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

### Tactics and Techniques
- **Tactic:** Collection
  - **Technique ID:** T1213.003
  - **Technique Name:** Data from Information Repositories: Cloud Storage
  - **Description:** Misconfigured Salesforce Aura endpoints allow unauthorized access to sensitive data such as credit card numbers, identity documents, and health information.

- **Tactic:** Discovery
  - **Technique ID:** T1087.002
  - **Technique Name:** Account Discovery: Domain Accounts
  - **Description:** Use of the `getConfigData` and `getItems` Aura methods to retrieve sensitive Salesforce object records.

- **Tactic:** Exfiltration
  - **Technique ID:** T1020
  - **Technique Name:** Automated Exfiltration
  - **Description:** Exploitation of GraphQL API to bypass Salesforce's 2,000-record retrieval limit and exfiltrate large datasets.

## 3. Malware & Tools

### Tools
- **AuraInspector:** Open-source tool released by Mandiant to identify and audit access control misconfigurations in Salesforce Aura.

### Techniques
- Abuse of Salesforce Aura methods (`getConfigData`, `getItems`, `getInitialListViews`, etc.) to retrieve sensitive data.
- Exploitation of GraphQL API for large-scale data retrieval.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor:** Not explicitly attributed to a specific group.
- **Campaign Name:** None identified.
- **Motivations:** Likely financial gain or espionage, given the sensitivity of the data exposed (e.g., credit card numbers, identity documents).
- **Targeted Sectors:** Organizations using Salesforce Experience Cloud, particularly those handling sensitive customer data.

## 5. Splunk Detection Searches

### Detecting Misuse of Aura Methods
```spl
index=proxy OR index=web
| search uri_path="/aura" AND (uri_query="*getConfigData*" OR uri_query="*getItems*" OR uri_query="*getInitialListViews*")
| stats count by src_ip, uri_path, uri_query
| where count > 10
```
*Comment:* Detects repeated access to Salesforce Aura methods that could indicate unauthorized data retrieval attempts.

### Detecting GraphQL API Exploitation
```spl
index=proxy OR index=web
| search uri_path="/graphql" AND http_method="POST"
| stats count by src_ip, uri_path, http_method
| where count > 5
```
*Comment:* Identifies potential abuse of the GraphQL API for large-scale data retrieval.

### Monitoring for Large Data Exfiltration
```spl
index=proxy OR index=web
| search uri_path="/aura" OR uri_path="/graphql"
| stats sum(bytes_out) as total_data_exfiltrated by src_ip
| where total_data_exfiltrated > 10000000
```
*Comment:* Flags IPs exfiltrating more than 10MB of data via Salesforce endpoints.

## 6. Executive Summary

Mandiant has released a new tool, AuraInspector, to help organizations identify misconfigurations in Salesforce Aura that could expose sensitive data. The report highlights the abuse of Salesforce Aura methods and the GraphQL API to bypass record retrieval limits and exfiltrate large datasets. Organizations using Salesforce Experience Cloud should immediately audit their access control configurations and monitor for suspicious activity on Salesforce endpoints. Recommended actions include deploying Splunk searches to detect misuse of Aura methods and GraphQL API exploitation, and ensuring proper access controls are in place.
