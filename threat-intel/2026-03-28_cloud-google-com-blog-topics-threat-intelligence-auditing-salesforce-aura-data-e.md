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

- **Tactic: Collection (TA0009)**
  - **Technique: Data from Information Repositories (T1213)**: Unauthorized access to Salesforce Aura endpoints to retrieve sensitive data such as credit card numbers, identity documents, and health information.

- **Tactic: Discovery (TA0007)**
  - **Technique: Application Window Discovery (T1010)**: Use of the `ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews` method to identify accessible Record Lists.
  - **Technique: Application Discovery (T1010)**: Use of the `ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData` method to identify administrative or configuration panels via Home URLs.

- **Tactic: Initial Access (TA0001)**
  - **Technique: Exploit Public-Facing Application (T1190)**: Exploitation of misconfigured Salesforce Aura endpoints to gain unauthorized access to sensitive data.

- **Tactic: Collection (TA0009)**
  - **Technique: Automated Collection (T1119)**: Use of the AuraInspector tool to automate the detection of misconfigurations and data exposures in Salesforce Aura.

## 3. Malware & Tools

### Tools
- **AuraInspector**: Open-source command-line tool developed by Mandiant to identify and audit access control misconfigurations in Salesforce Aura.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor**: Not specified.
- **Campaign Name**: Not specified.
- **Motivations**: Likely financial gain or data theft, targeting sensitive data such as credit card numbers, identity documents, and health information.
- **Targeted Sectors/Geographies**: Organizations using Salesforce Experience Cloud, potentially across various sectors.

## 5. Splunk Detection Searches

### Detecting Unauthorized Access to Salesforce Aura Endpoints
```spl
index=proxy_logs sourcetype=bluecoat:proxysg
| search uri_path="/aura" http_method=POST
| stats count by src_ip, uri_path, http_user_agent
| where count > 100
| table src_ip, uri_path, http_user_agent, count
```
*Comment: This search identifies IPs making excessive POST requests to the Salesforce Aura endpoint, which could indicate exploitation attempts.*

### Detecting Misuse of the `getConfigData` Method
```spl
index=proxy_logs sourcetype=bluecoat:proxysg
| search uri_path="/aura" http_method=POST "serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData"
| stats count by src_ip, uri_path, http_user_agent
| table src_ip, uri_path, http_user_agent, count
```
*Comment: This search detects usage of the `getConfigData` method, which could indicate attempts to retrieve sensitive backend object data.*

### Detecting GraphQL API Exploitation
```spl
index=proxy_logs sourcetype=bluecoat:proxysg
| search uri_path="/graphql" http_method=POST
| stats count by src_ip, uri_path, http_user_agent
| where count > 50
| table src_ip, uri_path, http_user_agent, count
```
*Comment: This search identifies potential misuse of the GraphQL API to retrieve large amounts of data.*

### Detecting Access to Administrative URLs
```spl
index=proxy_logs sourcetype=bluecoat:proxysg
| search uri_path="/s/recordlist/" OR uri_path="/admin" OR uri_path="/config"
| stats count by src_ip, uri_path, http_user_agent
| table src_ip, uri_path, http_user_agent
```
*Comment: This search identifies access to administrative or configuration pages that may be exposed due to misconfigurations.*

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, to help organizations identify and audit access control misconfigurations in Salesforce Aura. The report highlights a novel technique using the GraphQL API to bypass Salesforce's 2,000-record retrieval limit, which could be exploited in cases of misconfigured access controls. Additionally, the report outlines methods to identify administrative URLs, Record Lists, and self-registration pages that may be exposed due to misconfigurations. Organizations using Salesforce Experience Cloud are advised to review their access control configurations and implement the recommended mitigations to prevent unauthorized data access.