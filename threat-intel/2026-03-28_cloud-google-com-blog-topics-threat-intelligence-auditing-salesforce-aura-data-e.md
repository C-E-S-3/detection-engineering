---
scraped_at: 2026-01-12T00:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure/
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### Domains/URLs
- None identified

### IP Addresses
- None identified

### File Hashes
- None identified

### Other IOCs
- None identified

## 2. TTPs (MITRE ATT&CK Mapping)

### Tactic: Initial Access
- **T1190: Exploit Public-Facing Application**: Exploiting misconfigured Salesforce Aura endpoints to gain unauthorized access to sensitive data.

### Tactic: Collection
- **T1530: Data from Cloud Storage Object**: Using misconfigured Salesforce Aura endpoints to retrieve sensitive data such as credit card numbers, identity documents, and health information.

### Tactic: Discovery
- **T1087.002: Account Discovery: Domain Accounts**: Using the `getConfigData` and `getItems` Aura methods to enumerate Salesforce object records and permissions.
- **T1083: File and Directory Discovery**: Using the `getAppBootstrapData` Aura method to identify home URLs and administrative panels.

### Tactic: Exfiltration
- **T1020: Automated Exfiltration**: Leveraging Salesforce Aura's "boxcar'ing" feature to bulk retrieve up to 250 actions in a single request, optimizing data exfiltration.

## 3. Malware & Tools

### Tools
- **AuraInspector**: Open-source tool released by Mandiant to identify and audit access control misconfigurations in Salesforce Aura framework.

## 4. Threat Actor / Campaign Attribution
- **Threat Actor**: Not explicitly attributed to a specific threat actor.
- **Campaign**: No specific campaign mentioned.
- **Motivations**: Likely financial gain through unauthorized access to sensitive data such as credit card numbers, identity documents, and health information.
- **Targeted Sectors/Geographies**: Organizations using Salesforce Experience Cloud, potentially across various sectors.

## 5. Splunk Detection Searches

### Detecting Unauthorized Access to Salesforce Aura Endpoints
```spl
index=proxy OR index=web
sourcetype=access_combined OR sourcetype=web_proxy
"/aura" AND ("ACTION$getConfigData" OR "ACTION$getItems" OR "ACTION$getInitialListViews" OR "ACTION$getAppBootstrapData")
| stats count by src_ip, uri_path, http_user_agent
| where count > 10
```
*Comment: Detects repeated access to Salesforce Aura endpoints that may indicate unauthorized data retrieval attempts.*

### Detecting GraphQL API Misuse
```spl
index=proxy OR index=web
sourcetype=access_combined OR sourcetype=web_proxy
"graphql" AND "query"
| stats count by src_ip, uri_path, http_user_agent
| where count > 10
```
*Comment: Identifies potential misuse of the GraphQL API for unauthorized data retrieval.*

### Monitoring for Bulk Data Retrieval via Boxcar'ing
```spl
index=proxy OR index=web
sourcetype=access_combined OR sourcetype=web_proxy
"/aura" AND "Content-Length"
| stats avg(Content_Length) as avg_content_length, count by src_ip
| where avg_content_length > 100000
```
*Comment: Detects unusually large Content-Length values in requests to Salesforce Aura endpoints, which may indicate bulk data retrieval attempts.*

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, to help organizations identify and mitigate access control misconfigurations in Salesforce's Aura framework. These misconfigurations can expose sensitive data such as credit card numbers, identity documents, and health information. The report highlights previously undocumented techniques, including the use of GraphQL to bypass Salesforce's 2,000-record retrieval limit and the exploitation of the Aura framework's "boxcar'ing" feature for bulk data retrieval. Organizations using Salesforce Experience Cloud should immediately audit their configurations for potential misconfigurations and implement recommended security measures to mitigate these risks.