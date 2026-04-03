---
scraped_at: "2026-04-03T05:32:23Z"
source_url: "https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure/"
report_type: threat-intel
severity: "medium"
title: "AuraInspector Tool Identifies Salesforce Aura Misconfigurations and Exploitable GraphQL Techniques"
---

## 1. Indicators of Compromise (IOCs)
No specific IOCs (domains, IPs, hashes) were identified in the source.

## 2. TTPs (MITRE ATT&CK Mapping)
### TTPs Identified:
- **Tactic:** Initial Access
  - **Technique ID:** T1190
  - **Technique Name:** Exploit Public-Facing Application
  - **Description:** Exploiting misconfigured Salesforce Aura endpoints to access sensitive data.

- **Tactic:** Collection
  - **Technique ID:** T1213
  - **Technique Name:** Data from Information Repositories
  - **Description:** Using Aura methods and GraphQL API to retrieve large volumes of records from Salesforce objects.

- **Tactic:** Privilege Escalation
  - **Technique ID:** T1068
  - **Technique Name:** Exploitation for Privilege Escalation
  - **Description:** Leveraging misconfigurations in access control to escalate privileges and access unauthorized data.

## 3. Malware & Tools
### Tools:
- **AuraInspector:** An open-source tool released by Mandiant to identify and audit access control misconfigurations within the Salesforce Aura framework.

## 4. Threat Actor / Campaign Attribution
No specific threat actor or campaign attribution was provided in the source.

## 5. Splunk Detection Searches
### Detecting Misuse of Aura Methods
```spl
index=web sourcetype=access_combined
| search uri_path="/AuraServlet" "serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData"
| stats count by clientip, uri_path, http_user_agent
| table clientip, uri_path, http_user_agent, count
| sort - count
```
*Detects access to the Aura endpoint invoking the `getConfigData` method.*

### Detecting GraphQL API Abuse
```spl
index=web sourcetype=access_combined
| search uri_path="/graphql" "query"
| stats count by clientip, uri_path, http_user_agent
| table clientip, uri_path, http_user_agent, count
| sort - count
```
*Detects GraphQL API queries potentially used for data exfiltration.*

### Detecting Bulk Actions
```spl
index=web sourcetype=access_combined
| search uri_path="/AuraServlet" "actions" "descriptor" "ACTION$getItems"
| stats count by clientip, uri_path, http_user_agent
| table clientip, uri_path, http_user_agent, count
| sort - count
```
*Detects bulk actions sent to Salesforce Aura endpoints.*

## 6. Executive Summary
Mandiant has released AuraInspector, an open-source tool designed to identify misconfigurations in Salesforce Aura endpoints that could expose sensitive data such as credit card numbers and identity documents. The report highlights the exploitation of Aura methods and GraphQL API to bypass record retrieval limits and access unauthorized data. While Salesforce confirmed these methods respect object permissions, misconfigurations can lead to significant data exposure risks. Administrators are advised to audit their Salesforce configurations and leverage tools like AuraInspector to mitigate these risks.