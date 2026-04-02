---
scraped_at: "2026-04-02T22:02:29Z"
source_url: "https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure/"
report_type: threat-intel
severity: "medium"
title: "AuraInspector: Salesforce Aura Misconfigurations and GraphQL Exploitation"
---

## 1. Indicators of Compromise (IOCs)
No specific IOCs (IP addresses, domains, hashes, etc.) were identified in the source content.

## 2. TTPs (MITRE ATT&CK Mapping)
### Tactics and Techniques:
- **Tactic:** Initial Access
  - **Technique ID:** T1190
  - **Technique Name:** Exploit Public-Facing Application
  - **Description:** Exploiting misconfigured Salesforce Aura endpoints to retrieve sensitive data.

- **Tactic:** Discovery
  - **Technique ID:** T1087
  - **Technique Name:** Account Discovery
  - **Description:** Using Aura methods to enumerate accessible records and misconfigured permissions.

- **Tactic:** Collection
  - **Technique ID:** T1213
  - **Technique Name:** Data from Information Repositories
  - **Description:** Leveraging GraphQL API to bypass record retrieval limits and collect sensitive data.

## 3. Malware & Tools
### Tools:
- **AuraInspector:** Open-source tool released by Mandiant to identify and audit access control misconfigurations in Salesforce Aura.

## 4. Threat Actor / Campaign Attribution
No specific threat actor or campaign attribution was provided in the source content.

## 5. Splunk Detection Searches
### Detecting Misconfigured Aura Endpoints:
```spl
index=web sourcetype=access_combined
| search uri_path="/AuraEndpoint"
| stats count by client_ip, uri_path, http_method
| where count > 100
| table client_ip, uri_path, http_method, count
```
*Detects excessive access to Salesforce Aura endpoints, which may indicate exploitation attempts.*

### Detecting GraphQL API Usage:
```spl
index=web sourcetype=access_combined
| search uri_path="/graphql"
| stats count by client_ip, uri_path, http_method
| where count > 50
| table client_ip, uri_path, http_method, count
```
*Detects unusual activity targeting the GraphQL API, which may indicate data retrieval attempts.*

### Monitoring AuraInspector Tool Usage:
```spl
index=endpoint sourcetype=process
| search process="AuraInspector"
| stats count by user, process, parent_process
| table user, process, parent_process, count
```
*Detects execution of the AuraInspector tool on endpoints.*

## 6. Executive Summary
Mandiant has released AuraInspector, a tool to identify misconfigurations in Salesforce Aura endpoints that could expose sensitive data such as credit card numbers and identity documents. The report highlights the exploitation of Aura methods and the GraphQL API to bypass record retrieval limits and access misconfigured objects. Administrators are advised to audit Salesforce configurations and restrict access to sensitive endpoints.

Recommended actions:
1. Use AuraInspector to identify and remediate misconfigurations.
2. Monitor access to Salesforce Aura endpoints and GraphQL API.
3. Restrict unauthenticated access to sensitive Salesforce objects and endpoints.