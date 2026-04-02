---
scraped_at: "2026-04-02T10:02:38Z"
source_url: "https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure/"
report_type: threat-intel
severity: "medium"
title: "AuraInspector uncovers Salesforce Aura misconfigurations and GraphQL exploitation risks"
---

## 1. Indicators of Compromise (IOCs)
No specific IOCs (domains, IPs, hashes, etc.) were identified in the source.

## 2. TTPs (MITRE ATT&CK Mapping)
- **Tactic:** Initial Access
  - **Technique ID:** T1190
  - **Technique Name:** Exploit Public-Facing Application
  - **Description:** Exploiting misconfigured Salesforce Aura endpoints to access sensitive data.

- **Tactic:** Collection
  - **Technique ID:** T1213
  - **Technique Name:** Data from Information Repositories
  - **Description:** Using GraphQL API to retrieve records from Salesforce objects, bypassing standard record retrieval limits.

- **Tactic:** Credential Access
  - **Technique ID:** T1078
  - **Technique Name:** Valid Accounts
  - **Description:** Exploiting self-registration misconfigurations to gain unauthorized access to Salesforce accounts.

## 3. Malware & Tools
- **Tool:** AuraInspector
  - **Description:** Open-source tool released by Mandiant to identify and audit access control misconfigurations in Salesforce Aura framework.

## 4. Threat Actor / Campaign Attribution
No specific threat actor or campaign attribution was provided in the source.

## 5. Splunk Detection Searches
### Detecting unauthorized access to Salesforce Aura endpoints
```spl
index=web sourcetype=access_combined
| search uri_path="/aura" AND (uri_query="descriptor=*getConfigData*" OR uri_query="descriptor=*getItems*")
| stats count by clientip, uri_path, uri_query
| where count > 100
| table clientip, uri_path, uri_query, count
```
*Detects excessive requests to Salesforce Aura endpoints, which may indicate exploitation attempts.*

### Detecting GraphQL API exploitation
```spl
index=web sourcetype=access_combined
| search uri_path="/graphql" AND (uri_query="query=*" OR uri_query="mutation=*")
| stats count by clientip, uri_path, uri_query
| where count > 50
| table clientip, uri_path, uri_query, count
```
*Identifies potential abuse of the GraphQL API for unauthorized data retrieval.*

### Monitoring self-registration page access
```spl
index=web sourcetype=access_combined
| search uri_path="/self-registration"
| stats count by clientip, uri_path
| where count > 10
| table clientip, uri_path, count
```
*Flags repeated access attempts to the self-registration page, which may indicate exploitation of misconfigured self-registration settings.*

## 6. Executive Summary
Mandiant has released a new tool, AuraInspector, to help administrators identify and audit misconfigurations in Salesforce Aura framework endpoints. These misconfigurations can lead to unauthorized access to sensitive data, including credit card numbers and identity documents. Additionally, the report highlights the exploitation of Salesforce's GraphQL API to bypass record retrieval limits, which could be leveraged in cases of misconfigured access controls. Organizations using Salesforce should immediately audit their Aura endpoints, review access control settings, and ensure self-registration is properly disabled to mitigate potential risks.