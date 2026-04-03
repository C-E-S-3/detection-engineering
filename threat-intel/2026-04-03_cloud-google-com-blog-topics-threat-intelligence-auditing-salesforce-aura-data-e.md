---
scraped_at: "2026-04-03T07:02:23Z"
source_url: "https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure/"
report_type: threat-intel
severity: "medium"
title: "AuraInspector uncovers Salesforce Aura framework misconfigurations enabling unauthorized data access"
---

## 1. Indicators of Compromise (IOCs)
No specific IOCs (e.g., IPs, domains, hashes) were identified in the source.

## 2. TTPs (MITRE ATT&CK Mapping)
### Tactics and Techniques:
- **Tactic:** Initial Access
  - **Technique ID:** T1190
  - **Technique Name:** Exploit Public-Facing Application
  - **Description:** Misconfigured Salesforce Aura endpoints allow unauthorized access to sensitive data.

- **Tactic:** Discovery
  - **Technique ID:** T1087
  - **Technique Name:** Account Discovery
  - **Description:** Exploitation of Salesforce Aura methods to retrieve sensitive account information.

- **Tactic:** Collection
  - **Technique ID:** T1213
  - **Technique Name:** Data from Information Repositories
  - **Description:** Unauthorized retrieval of sensitive data such as credit card numbers, identity documents, and health information from Salesforce objects.

- **Tactic:** Impact
  - **Technique ID:** T1485
  - **Technique Name:** Data Destruction
  - **Description:** Misconfigured access controls could allow unauthorized users to modify or delete records.

## 3. Malware & Tools
- **Tool Name:** AuraInspector
  - **Description:** Open-source command-line tool released by Mandiant to identify and audit access control misconfigurations in Salesforce Aura framework.

## 4. Threat Actor / Campaign Attribution
No specific threat actor or campaign attribution was provided in the source.

## 5. Splunk Detection Searches
### Detecting unauthorized access to Salesforce Aura endpoints:
```spl
index=web sourcetype=access_combined
| search uri_path="/s/recordlist/*" OR uri_path="/apex/*" OR uri_path="/graphql"
| stats count by clientip, uri_path, http_user_agent
| sort - count
```
*Detects access to Salesforce Aura endpoints that may indicate unauthorized access attempts.*

### Monitoring for unusual data retrieval patterns:
```spl
index=web sourcetype=access_combined
| search uri_path="/graphql" OR uri_path="/apex/*"
| stats count by clientip, uri_path, http_user_agent
| where count > 2000
| table clientip, uri_path, count, http_user_agent
```
*Identifies potential abuse of GraphQL API or Aura methods to bypass record limits.*

### Detecting bulk action requests:
```spl
index=web sourcetype=access_combined
| search uri_path="/graphql" OR uri_path="/apex/*"
| rex field=_raw "Content-Length:\s(?<content_length>\d+)"
| eval content_length_mb = content_length / 1024 / 1024
| where content_length_mb > 10
| table clientip, uri_path, content_length_mb
```
*Detects large bulk action requests that may indicate attempts to exploit Salesforce Aura misconfigurations.*

## 6. Executive Summary
Mandiant has released a new tool, AuraInspector, to help identify and audit access control misconfigurations in the Salesforce Aura framework. These misconfigurations can allow unauthorized users to access sensitive data, including credit card numbers, identity documents, and health information. The report highlights novel techniques for exploiting Salesforce Aura endpoints, such as using GraphQL to bypass record retrieval limits and leveraging misconfigured access controls to retrieve sensitive data. Organizations using Salesforce should immediately audit their Aura endpoints and access control configurations to mitigate potential exposure.