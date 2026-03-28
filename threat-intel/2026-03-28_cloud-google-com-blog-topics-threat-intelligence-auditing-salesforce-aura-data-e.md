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

### Other
- None identified

## 2. TTPs (MITRE ATT&CK Mapping)

### Tactics and Techniques
- **Tactic:** Collection
  - **Technique ID:** T1530
  - **Technique Name:** Data from Cloud Storage Object
  - **Description:** Misconfigured Salesforce Aura endpoints allow unauthorized access to sensitive data, such as credit card numbers and identity documents.

- **Tactic:** Discovery
  - **Technique ID:** T1592
  - **Technique Name:** Gather Victim Host Information
  - **Description:** Use of GraphQL API to retrieve metadata and records from Salesforce objects.

- **Tactic:** Exfiltration
  - **Technique ID:** T1041
  - **Technique Name:** Exfiltration Over C2 Channel
  - **Description:** Exploitation of Salesforce Aura misconfigurations to exfiltrate sensitive data through legitimate API calls.

## 3. Malware & Tools

### Tools
- **AuraInspector:** An open-source tool developed by Mandiant to identify and audit access control misconfigurations in Salesforce Aura.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor:** Not specified
- **Campaign Name:** Not specified
- **Motivations:** Likely financial gain or data theft
- **Targeted Sectors/Geographies:** Organizations using Salesforce Experience Cloud, particularly those with misconfigured access controls.

## 5. Splunk Detection Searches

### Behavioral TTPs

#### Detecting Unauthorized Access to Salesforce Aura Endpoints
```spl
index=proxy_logs sourcetype=bluecoat:proxysg
| search uri_path="/aura" AND http_method=POST
| table _time, src_ip, dest_ip, uri_path, http_method, http_user_agent, http_referrer
| stats count by src_ip, dest_ip, uri_path
| where count > 100
```
*Comment: Detects high-frequency POST requests to Salesforce Aura endpoints, which may indicate unauthorized access attempts.*

#### Detecting GraphQL API Misuse
```spl
index=proxy_logs sourcetype=bluecoat:proxysg
| search uri_path="/graphql" AND http_method=POST
| table _time, src_ip, dest_ip, uri_path, http_method, http_user_agent, http_referrer
| stats count by src_ip, dest_ip, uri_path
| where count > 50
```
*Comment: Identifies potential misuse of the GraphQL API for data exfiltration.*

### Endpoint IOCs

#### Monitoring for Suspicious Aura Method Calls
```spl
index=application_logs sourcetype=salesforce:aura
| search "ACTION$getConfigData" OR "ACTION$getItems" OR "ACTION$getInitialListViews" OR "ACTION$getAppBootstrapData"
| table _time, user, action, params
```
*Comment: Monitors for specific Aura method calls that may indicate exploitation of misconfigurations.*

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, to identify and audit access control misconfigurations in Salesforce Aura. These misconfigurations can expose sensitive data such as credit card numbers and identity documents to unauthorized users. The report highlights a previously undocumented technique using the GraphQL API to bypass Salesforce's 2,000-record retrieval limit, enabling attackers to exfiltrate large datasets. Organizations using Salesforce Experience Cloud should immediately review their access control configurations and monitor for suspicious API activity.