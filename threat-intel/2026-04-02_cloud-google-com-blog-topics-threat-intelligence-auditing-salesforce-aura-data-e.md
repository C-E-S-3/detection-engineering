---
scraped_at: "2026-04-02T07:02:27Z"
source_url: "https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure/"
report_type: threat-intel
severity: "medium"
title: "AuraInspector reveals Salesforce Aura misconfigurations and GraphQL exploitation risks"
---

## 1. Indicators of Compromise (IOCs)
No concrete IOCs (IP addresses, domains, hashes, etc.) were provided in the source.

## 2. TTPs (MITRE ATT&CK Mapping)
### Tactics and Techniques:
- **Tactic:** Initial Access
  - **Technique ID:** T1190
  - **Technique Name:** Exploit Public-Facing Application
  - **Description:** Exploiting misconfigured Salesforce Aura endpoints and GraphQL controllers to access sensitive data.

- **Tactic:** Collection
  - **Technique ID:** T1213
  - **Technique Name:** Data from Information Repositories
  - **Description:** Retrieving sensitive records from Salesforce objects using Aura methods and GraphQL queries.

- **Tactic:** Defense Evasion
  - **Technique ID:** T1562
  - **Technique Name:** Impair Defenses
  - **Description:** Bypassing record retrieval limits using sorting parameters and GraphQL pagination.

## 3. Malware & Tools
### Tools:
- **AuraInspector:** An open-source tool released by Mandiant to audit Salesforce Aura misconfigurations and data exposures.

## 4. Threat Actor / Campaign Attribution
No specific threat actors or campaigns were attributed in the source.

## 5. Splunk Detection Searches
### Detecting Misconfigured Aura Endpoints:
```spl
index=web sourcetype=access_combined
| search uri_path="/AuraServlet" OR uri_path="/graphql"
| stats count by uri_path, http_method, src_ip
| where count > 100
| table uri_path, http_method, src_ip, count
```
*Detects excessive access to Salesforce Aura or GraphQL endpoints.*

### Detecting Unauthorized Record Retrieval:
```spl
index=web sourcetype=access_combined
| search uri_path="/AuraServlet" "ACTION$getItems" "ACTION$getConfigData"
| stats count by src_ip, uri_path, http_method, user_agent
| where count > 50
| table src_ip, uri_path, http_method, user_agent, count
```
*Identifies repeated attempts to retrieve records using Aura methods.*

### Monitoring GraphQL Queries:
```spl
index=web sourcetype=access_combined
| search uri_path="/graphql" "query" "mutation"
| stats count by src_ip, uri_path, http_method, user_agent
| where count > 50
| table src_ip, uri_path, http_method, user_agent, count
```
*Detects high-frequency GraphQL queries or mutations.*

## 6. Executive Summary
Mandiant has released AuraInspector, a tool to identify misconfigurations in Salesforce Aura endpoints. These misconfigurations can allow unauthorized access to sensitive data, including credit card numbers and identity documents. Additionally, exploitation of the GraphQL Aura controller enables attackers to bypass record retrieval limits and access large datasets. Administrators should audit their Salesforce configurations and restrict access to public-facing endpoints. Immediate actions include deploying AuraInspector, monitoring endpoint activity, and validating access control settings.
