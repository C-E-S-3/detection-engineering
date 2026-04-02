---
scraped_at: "2026-04-02T05:32:41Z"
source_url: "https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure/"
report_type: threat-intel
severity: "medium"
title: "AuraInspector uncovers Salesforce Aura misconfigurations and GraphQL exploitation risks"
---

## 1. Indicators of Compromise (IOCs)
No specific IOCs (IP addresses, domains, hashes) were identified in the source content.

## 2. TTPs (MITRE ATT&CK Mapping)
### Tactics and Techniques
- **Tactic:** Initial Access
  - **Technique ID:** T1190
  - **Technique Name:** Exploit Public-Facing Application
  - **Description:** Exploiting misconfigured Salesforce Aura endpoints to retrieve sensitive data.

- **Tactic:** Collection
  - **Technique ID:** T1213
  - **Technique Name:** Data from Information Repositories
  - **Description:** Using GraphQL API to bypass record retrieval limits and access large datasets.

- **Tactic:** Credential Access
  - **Technique ID:** T1556
  - **Technique Name:** Modify Authentication Process
  - **Description:** Exploiting self-registration misconfigurations to create authenticated accounts.

## 3. Malware & Tools
### Tools
- **AuraInspector:** Open-source tool released by Mandiant to identify and audit access control misconfigurations in Salesforce Aura framework.

## 4. Threat Actor / Campaign Attribution
No specific threat actor or campaign attribution was provided in the source content.

## 5. Splunk Detection Searches
### Detecting Misconfigured Aura Endpoints
```spl
index=web sourcetype=access_combined
| search uri_path="/AuraEndpoint" "serviceComponent://"
| stats count by uri_path, http_method, src_ip
| where count > 100
```
*Detects excessive access to Salesforce Aura endpoints, which may indicate exploitation attempts.*

### Detecting GraphQL Exploitation
```spl
index=web sourcetype=access_combined
| search uri_path="/graphql" "query"
| stats count by src_ip, uri_path, http_method
| where count > 50
```
*Identifies potential abuse of GraphQL API for data retrieval.*

### Monitoring Self-Registration Exploitation
```spl
index=web sourcetype=access_combined
| search uri_path="/self-registration"
| stats count by src_ip, uri_path, http_method
| where count > 10
```
*Flags repeated access to self-registration pages, which may indicate exploitation.*

## 6. Executive Summary
Mandiant has released AuraInspector, a tool designed to identify misconfigurations in Salesforce Aura framework that could expose sensitive data. Key risks include exploiting Aura endpoints to retrieve unauthorized records, bypassing record limits using GraphQL API, and abusing self-registration misconfigurations to gain authenticated access. Administrators are advised to audit access controls, disable unnecessary endpoints, and monitor for unusual activity around Aura and GraphQL APIs. Immediate remediation of misconfigurations is critical to prevent unauthorized data access.