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
    - **Sub-technique:** Data from Local System (T1213.001)
    - **Description:** Exploitation of Salesforce Aura misconfigurations to retrieve sensitive data such as credit card numbers, identity documents, and health information.

- **Tactic:** Discovery (TA0007)
  - **Technique:** Application Layer Protocol (T1071)
    - **Sub-technique:** Web Protocols (T1071.001)
    - **Description:** Abuse of Salesforce Aura endpoints to invoke methods like `getConfigData`, `getItems`, and GraphQL queries to retrieve sensitive records.

- **Tactic:** Initial Access (TA0001)
  - **Technique:** Exploit Public-Facing Application (T1190)
    - **Description:** Exploitation of misconfigured Salesforce Aura endpoints and GraphQL controllers accessible to unauthenticated users.

## 3. Malware & Tools

### Tools
- **AuraInspector**: An open-source tool released by Mandiant to identify and audit access control misconfigurations in Salesforce Aura.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor:** Not explicitly attributed to a specific group.
- **Campaign Name:** Not specified.
- **Motivations:** Likely financial gain or data theft, targeting sensitive data such as credit card numbers, identity documents, and health information.
- **Targeted Sectors/Geographies:** Organizations using Salesforce Experience Cloud, potentially across various industries.

## 5. Splunk Detection Searches

### Detecting Misuse of Salesforce Aura Endpoints
```spl
index=proxy sourcetype=bluecoat:proxysg
| search uri_path="/aura" OR uri_path="/graphql"
| stats count by src_ip, uri_path, http_method, http_status
| where http_status=200
| table src_ip, uri_path, http_method, http_status, count
```
*Comment: This search identifies access to Salesforce Aura or GraphQL endpoints, focusing on successful responses (HTTP 200).*

### Detecting Large Data Exfiltration via Aura Endpoints
```spl
index=proxy sourcetype=bluecoat:proxysg
| search uri_path="/aura" method="POST"
| rex field=_raw "Content-Length:\s(?<content_length>\d+)"
| stats sum(content_length) as total_data_transferred by src_ip
| where total_data_transferred > 1000000
| table src_ip, total_data_transferred
```
*Comment: This search identifies potential large data exfiltration through Salesforce Aura endpoints by analyzing POST requests with high data transfer volumes.*

### Detecting GraphQL Queries
```spl
index=proxy sourcetype=bluecoat:proxysg
| search uri_path="/graphql" method="POST"
| stats count by src_ip, uri_path, http_method, http_status
| table src_ip, uri_path, http_method, http_status, count
```
*Comment: This search detects GraphQL queries made to Salesforce instances, which could indicate potential misuse of the GraphQL API.*

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, to help organizations identify and remediate access control misconfigurations in Salesforce Aura. These misconfigurations can expose sensitive data such as credit card numbers, identity documents, and health information. The report highlights the abuse of Salesforce Aura endpoints and GraphQL APIs to bypass record retrieval limits and access sensitive data. Organizations using Salesforce Experience Cloud are advised to review their access control configurations, disable unnecessary features like self-registration, and monitor for unauthorized access to Salesforce endpoints. Immediate action is recommended to mitigate potential data exposure risks.