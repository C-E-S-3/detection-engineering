---
scraped_at: "2026-01-12T00:00:00Z"
source_url: "https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure/"
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

No specific IOCs (IP addresses, domains, hashes, etc.) were identified in the source content.

## 2. TTPs (MITRE ATT&CK Mapping)

### Tactics and Techniques Identified:

- **Tactic: Initial Access**
  - **Technique ID:** T1078.003 (Valid Accounts: Local Accounts)
    - **Description:** Exploiting misconfigured access controls in Salesforce Aura framework to gain unauthorized access to sensitive data such as credit card numbers, identity documents, and health information.

- **Tactic: Discovery**
  - **Technique ID:** T1592 (Gather Victim Host Information)
    - **Description:** Using the `getConfigData` Aura method to retrieve a list of objects used in the backend Salesforce database.

  - **Technique ID:** T1596.001 (Search Open Websites/Domains: Open Websites/Domains)
    - **Description:** Leveraging the `CMCAppController/ACTION$getAppBootstrapData` Aura method to identify home URLs, including administrative or configuration panels for third-party Salesforce modules.

- **Tactic: Collection**
  - **Technique ID:** T1530 (Data from Cloud Storage Object)
    - **Description:** Using the `getItems` Aura method with the `sortBy` parameter to bypass Salesforce's 2,000-record retrieval limit and access additional records.

  - **Technique ID:** T1530 (Data from Cloud Storage Object)
    - **Description:** Exploiting the GraphQL Aura controller to retrieve all records tied to a misconfigured Salesforce object, bypassing the 2,000-record limit.

- **Tactic: Credential Access**
  - **Technique ID:** T1556.004 (Credential API Hooking)
    - **Description:** Using the `LoginFormController` methods `getIsSelfRegistrationEnabled` and `getSelfRegistrationUrl` to identify and exploit self-registration functionality for unauthorized account creation.

## 3. Malware & Tools

- **Tool:** AuraInspector
  - **Description:** An open-source, command-line tool developed by Mandiant to identify and audit access control misconfigurations in Salesforce Aura.

## 4. Threat Actor / Campaign Attribution

- **Attribution:** No specific threat actor or campaign was identified in the source.
- **Motivation:** Likely opportunistic attackers exploiting misconfigurations to gain unauthorized access to sensitive Salesforce data.
- **Targeted Sectors:** Organizations using Salesforce Experience Cloud.

## 5. Splunk Detection Searches

### Detecting Misuse of Aura Methods

#### Search for `getConfigData` Method Usage
```spl
index=proxy OR index=web
| search uri_path="/Aura" AND http_method="POST"
| spath input=_raw path="actions{}.descriptor"
| search "actions{}.descriptor"="serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData"
| table _time, src_ip, uri_path, http_method, "actions{}.descriptor"
```
*Comment: Detects unauthorized use of the `getConfigData` Aura method.*

#### Search for `getItems` Method with `sortBy` Parameter
```spl
index=proxy OR index=web
| search uri_path="/Aura" AND http_method="POST"
| spath input=_raw path="actions{}.params.sortBy"
| search "actions{}.params.sortBy"="*"
| table _time, src_ip, uri_path, http_method, "actions{}.params.sortBy"
```
*Comment: Detects attempts to bypass record limits using the `sortBy` parameter in the `getItems` method.*

#### Search for GraphQL Aura Controller Usage
```spl
index=proxy OR index=web
| search uri_path="/Aura" AND http_method="POST"
| spath input=_raw path="actions{}.descriptor"
| search "actions{}.descriptor"="serviceComponent://ui.force.components.controllers.graphql.GraphQLController/ACTION$query"
| table _time, src_ip, uri_path, http_method, "actions{}.descriptor"
```
*Comment: Detects usage of the GraphQL Aura controller for data retrieval.*

#### Search for Self-Registration Methods
```spl
index=proxy OR index=web
| search uri_path="/Aura" AND http_method="POST"
| spath input=_raw path="actions{}.descriptor"
| search "actions{}.descriptor"="apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled" OR "actions{}.descriptor"="apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl"
| table _time, src_ip, uri_path, http_method, "actions{}.descriptor"
```
*Comment: Detects attempts to identify and exploit self-registration functionality.*

## 6. Executive Summary

Mandiant has released AuraInspector, an open-source tool designed to identify and audit access control misconfigurations in Salesforce Aura. The report highlights several techniques attackers could use to exploit these misconfigurations, including the misuse of Aura methods (`getConfigData`, `getItems`, and GraphQL controllers) to retrieve sensitive records and bypass Salesforce's 2,000-record limit. Additionally, attackers could exploit self-registration functionality to create unauthorized accounts. Organizations using Salesforce should immediately review their access control configurations, disable unnecessary self-registration, and monitor for suspicious activity using the provided detection searches.