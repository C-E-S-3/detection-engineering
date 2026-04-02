---
scraped_at: "2026-04-02T03:02:30Z"
source_url: "https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure/"
report_type: threat-intel
severity: "medium"
title: "AuraInspector tool identifies Salesforce Aura misconfigurations and GraphQL exploitation risks"
---

## 1. Indicators of Compromise (IOCs)
No specific IOCs (domains, IPs, hashes) were identified in the source.

## 2. TTPs (MITRE ATT&CK Mapping)
### Tactics and Techniques:
- **Tactic:** Initial Access
  - **Technique:** Exploit Public-Facing Application (T1190)
    - **Description:** Exploiting misconfigured Salesforce Aura endpoints to gain unauthorized access to sensitive data.
- **Tactic:** Collection
  - **Technique:** Data from Information Repositories (T1213)
    - **Description:** Using Salesforce Aura methods and GraphQL API to retrieve sensitive records and bypass record retrieval limits.
- **Tactic:** Credential Access
  - **Technique:** Exploit Application Access Token (T1528)
    - **Description:** Leveraging misconfigured self-registration settings to gain authenticated access.

## 3. Malware & Tools
### Tools:
- **AuraInspector:** Open-source tool developed by Mandiant to audit Salesforce Aura misconfigurations and identify data exposure risks.

## 4. Threat Actor / Campaign Attribution
No specific threat actor or campaign attribution was provided in the source.

## 5. Splunk Detection Searches
### Detection for Salesforce Aura Misconfigurations:
#### Detect unauthorized access to Aura endpoints:
```spl
index=web_logs sourcetype=access_combined
| search uri_path="/s/recordlist/*"
| stats count by client_ip, uri_path
| where count > 100
| table client_ip, uri_path, count
```
*Detects excessive access to Salesforce Aura record list endpoints.*

#### Detect GraphQL exploitation:
```spl
index=web_logs sourcetype=access_combined
| search uri_path="/graphql" "POST"
| stats count by client_ip, uri_path
| where count > 50
| table client_ip, uri_path, count
```
*Identifies suspicious GraphQL API usage.*

#### Detect self-registration exploitation:
```spl
index=web_logs sourcetype=access_combined
| search uri_path="/self-registration"
| stats count by client_ip, uri_path
| where count > 10
| table client_ip, uri_path, count
```
*Flags potential abuse of self-registration pages.*

## 6. Executive Summary
Mandiant has released AuraInspector, a tool to audit Salesforce Aura framework misconfigurations that could expose sensitive data such as credit card numbers and identity documents. The report highlights risks associated with exploiting misconfigured Aura endpoints, leveraging GraphQL APIs to bypass record retrieval limits, and abusing self-registration settings. Administrators are advised to use AuraInspector to identify and remediate these misconfigurations promptly. Immediate actions include auditing Salesforce access controls, disabling unnecessary self-registration features, and monitoring for suspicious activity on Aura and GraphQL endpoints.