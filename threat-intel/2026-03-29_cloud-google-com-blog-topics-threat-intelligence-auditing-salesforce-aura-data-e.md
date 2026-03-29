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
- **Tactic:** Collection
  - **Technique ID:** T1213.003 (Data from Information Repositories: SharePoint)
  - **Description:** Misconfigured Salesforce Aura endpoints allow unauthorized access to sensitive data, including credit card numbers, identity documents, and health information.

- **Tactic:** Discovery
  - **Technique ID:** T1087.002 (Account Discovery: Domain Accounts)
  - **Description:** Misconfigured Aura methods allow attackers to retrieve records for Salesforce objects, including user accounts and sensitive data.

- **Tactic:** Collection
  - **Technique ID:** T1530 (Data from Cloud Storage Object)
  - **Description:** Abuse of Salesforce GraphQL API to bypass record retrieval limits and access large datasets.

- **Tactic:** Defense Evasion
  - **Technique ID:** T1562.001 (Impair Defenses: Disable or Modify Tools)
  - **Description:** Abuse of Salesforce Aura’s "boxcar'ing" mechanism to bulk actions and evade detection.

## 3. Malware & Tools

### Tools
- **AuraInspector:** Open-source tool released by Mandiant to identify and audit access control misconfigurations in Salesforce Aura framework.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor:** None explicitly mentioned.
- **Campaign:** None explicitly mentioned.
- **Motivations:** Likely financial gain through unauthorized access to sensitive data such as credit card numbers, identity documents, and health information.

## 5. Splunk Detection Searches

### Detecting Unauthorized Access to Salesforce Aura Endpoints
```spl
index=proxy sourcetype=bluecoat:proxysg
| search uri_path="*/serviceComponent://ui.force.components.controllers.*"
| stats count by src_ip, uri_path, http_user_agent
| where count > 10
| table src_ip, uri_path, http_user_agent, count
```
*Comment: This search identifies potential abuse of Salesforce Aura endpoints by looking for unusual activity patterns.*

### Detecting GraphQL API Abuse
```spl
index=proxy sourcetype=bluecoat:proxysg
| search uri_path="*/graphql" http_method=POST
| stats count by src_ip, uri_path, http_user_agent
| where count > 10
| table src_ip, uri_path, http_user_agent, count
```
*Comment: This search identifies potential abuse of the Salesforce GraphQL API by monitoring for high-frequency POST requests to GraphQL endpoints.*

### Detecting Bulk Action Abuse
```spl
index=proxy sourcetype=bluecoat:proxysg
| search uri_path="*/serviceComponent://ui.force.components.controllers.*" http_method=POST
| rex field=_raw "Content-Length: (?<content_length>\d+)"
| eval content_length=tonumber(content_length)
| where content_length > 100000
| stats count by src_ip, uri_path, http_user_agent, content_length
```
*Comment: This search identifies potential abuse of the "boxcar'ing" mechanism by detecting unusually large POST requests to Salesforce Aura endpoints.*

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, to identify and audit access control misconfigurations in Salesforce Aura, a framework used in Salesforce applications. The report highlights several novel techniques, including the abuse of Salesforce Aura methods and the GraphQL API to bypass data retrieval limits and access sensitive data. These techniques exploit misconfigurations in Salesforce environments, potentially exposing sensitive information such as credit card numbers, identity documents, and health information. Immediate actions include deploying the AuraInspector tool, reviewing access control configurations, and monitoring for suspicious activity on Salesforce endpoints.