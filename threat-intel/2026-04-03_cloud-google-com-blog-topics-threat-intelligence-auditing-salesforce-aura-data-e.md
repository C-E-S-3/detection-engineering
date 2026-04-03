---
scraped_at: "2026-04-03T02:32:26Z"
source_url: "https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure/"
report_type: threat-intel
severity: "medium"
title: "AuraInspector uncovers Salesforce Aura misconfigurations enabling unauthorized data access"
---

## 1. Indicators of Compromise (IOCs)
No specific IOCs (e.g., domains, IPs, hashes) were identified in the source.

## 2. TTPs (MITRE ATT&CK Mapping)
- **Tactic:** Initial Access
  - **Technique ID:** T1078
  - **Technique Name:** Valid Accounts
  - **Description:** Exploitation of misconfigured Salesforce Aura access controls to gain unauthorized access to sensitive data.

- **Tactic:** Collection
  - **Technique ID:** T1213
  - **Technique Name:** Data from Information Repositories
  - **Description:** Use of Salesforce Aura methods and GraphQL API to retrieve sensitive records from misconfigured objects.

- **Tactic:** Defense Evasion
  - **Technique ID:** T1070.004
  - **Technique Name:** Indicator Removal on Host: File Deletion
  - **Description:** Potential abuse of Salesforce Aura methods to modify or delete records in misconfigured Salesforce objects.

## 3. Malware & Tools
- **Tool:** AuraInspector
  - **Description:** Open-source tool released by Mandiant to identify and audit access control misconfigurations in Salesforce Aura.

## 4. Threat Actor / Campaign Attribution
No specific threat actor or campaign was attributed in the source.

## 5. Splunk Detection Searches
### Detecting unauthorized access to Salesforce Aura endpoints
```spl
index=proxy sourcetype=bluecoat:proxysg
| search uri_path="/s/recordlist/*" OR uri_path="/apex/*"
| stats count by src_ip, uri_path
| sort - count
```
*This search identifies IPs accessing Salesforce Aura endpoints that may indicate unauthorized access attempts.*

### Detecting GraphQL API misuse
```spl
index=proxy sourcetype=bluecoat:proxysg
| search uri_path="/graphql"
| stats count by src_ip, uri_path
| sort - count
```
*This search identifies potential misuse of the GraphQL API for unauthorized data retrieval.*

### Detecting bulk actions in Salesforce Aura
```spl
index=proxy sourcetype=bluecoat:proxysg
| search uri_path="/aura" "Content-Length" > 100000
| stats count by src_ip, uri_path
| sort - count
```
*This search identifies large bulk requests to Salesforce Aura endpoints, which may indicate exploitation of the boxcar’ing mechanism.*

## 6. Executive Summary
Mandiant has released AuraInspector, a tool designed to identify and audit misconfigurations in Salesforce Aura, a framework used in Salesforce Experience Cloud applications. Misconfigurations in Aura endpoints can allow unauthorized users to access sensitive data, including credit card numbers and identity documents. Additionally, the Salesforce GraphQL API can be exploited to bypass record retrieval limits, enabling attackers to access large datasets from misconfigured objects. Administrators are advised to audit their Salesforce configurations and use AuraInspector to identify potential vulnerabilities.