---
scraped_at: "2026-04-02T01:32:25Z"
source_url: "https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure/"
report_type: threat-intel
severity: "medium"
title: "AuraInspector uncovers Salesforce Aura misconfigurations and GraphQL exploitation risks"
---

## 1. Indicators of Compromise (IOCs)
### Domains
No new domains identified.

### Hashes
No new hashes identified.

### IPs
No new IPs identified.

## 2. TTPs (MITRE ATT&CK Mapping)
### Tactics and Techniques
- **Tactic:** Initial Access
  - **Technique ID:** T1190 (Exploit Public-Facing Application)
  - **Description:** Exploiting misconfigured Salesforce Aura endpoints to access sensitive data.

- **Tactic:** Collection
  - **Technique ID:** T1213 (Data from Information Repositories)
  - **Description:** Using GraphQL API to retrieve records from Salesforce objects, bypassing standard record retrieval limits.

- **Tactic:** Persistence
  - **Technique ID:** T1136 (Create Account)
  - **Description:** Exploiting self-registration misconfigurations to create unauthorized accounts.

## 3. Malware & Tools
### Tools
- **AuraInspector:** Open-source tool released by Mandiant to identify and audit access control misconfigurations in Salesforce Aura framework.

## 4. Threat Actor / Campaign Attribution
No specific threat actor or campaign attribution provided in the source.

## 5. Splunk Detection Searches
### Detecting Misconfigured Aura Endpoints
```spl
index=web sourcetype=access_combined
| search "POST /aura" "serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData"
| stats count by clientip, uri, http_user_agent
| sort - count
```
*Detects requests to the `getConfigData` Aura endpoint, which may indicate attempts to exploit misconfigurations.*

### Detecting GraphQL API Exploitation
```spl
index=web sourcetype=access_combined
| search "POST /graphql" "serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData"
| stats count by clientip, uri, http_user_agent
| sort - count
```
*Detects unauthorized access attempts to the GraphQL Aura controller.*

### Detecting Self-Registration Exploitation
```spl
index=web sourcetype=access_combined
| search "POST /applauncher.LoginFormController/ACTION$getSelfRegistrationUrl"
| stats count by clientip, uri, http_user_agent
| sort - count
```
*Detects attempts to retrieve self-registration status and URL.*

## 6. Executive Summary
Mandiant has released AuraInspector, a tool designed to identify misconfigurations in Salesforce Aura framework, which could expose sensitive data such as credit card numbers and identity documents. The report highlights risks associated with exploiting Aura endpoints, GraphQL API, and self-registration misconfigurations. Organizations using Salesforce should immediately audit their configurations to prevent unauthorized access and data exposure. Recommended actions include deploying AuraInspector, reviewing access control settings, and disabling self-registration where unnecessary.