---
scraped_at: 2026-01-12T00:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure/
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### IP Addresses
_None identified_

### Domains/URLs
- None identified

### File Hashes
_None identified_

### Email Addresses
_None identified_

### File Names/Paths
_None identified_

### Registry Keys
_None identified_

### Mutex Names
_None identified_

### C2 Infrastructure
_None identified_

## 2. TTPs (MITRE ATT&CK Mapping)

- **Tactic: Initial Access (TA0001)**
  - **Technique: Exploit Public-Facing Application (T1190)**
    - Exploitation of Salesforce Aura misconfigurations to gain unauthorized access to sensitive data such as credit card numbers, identity documents, and health information.

- **Tactic: Collection (TA0009)**
  - **Technique: Data from Information Repositories (T1213)**
    - Use of Salesforce Aura methods like `getConfigData` and `getItems` to retrieve sensitive data from Salesforce objects.
  - **Technique: Automated Collection (T1119)**
    - Abuse of Salesforce Aura's "boxcar'ing" mechanism to bulk retrieve records for multiple objects in a single request.

- **Tactic: Discovery (TA0007)**
  - **Technique: Application Window Discovery (T1010)**
    - Use of `getInitialListViews` Aura method to identify accessible Record Lists and associated objects.
  - **Technique: Application Discovery (T1010)**
    - Use of `getAppBootstrapData` Aura method to identify home URLs leading to administrative or configuration panels.

- **Tactic: Credential Access (TA0006)**
  - **Technique: Account Manipulation (T1098)**
    - Exploitation of misconfigured self-registration settings to create unauthorized accounts with elevated access.

- **Tactic: Collection (TA0009)**
  - **Technique: Data from Information Repositories (T1213)**
    - Use of GraphQL API to bypass Salesforce's 2,000-record retrieval limit and access additional records.

## 3. Malware & Tools

- **AuraInspector**: An open-source tool released by Mandiant to identify and audit access control misconfigurations in Salesforce Aura.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor**: Not explicitly attributed to a specific group.
- **Campaign Name**: Not specified.
- **Motivations**: Likely financial gain or data theft, targeting organizations using Salesforce Experience Cloud.
- **Targeted Sectors/Geographies**: Organizations leveraging Salesforce Experience Cloud, potentially across multiple sectors.

## 5. Splunk Detection Searches

### Detecting Misuse of Aura Methods
```spl
index=proxy sourcetype=bluecoat | rex field=uri_path "(?<method>serviceComponent://[^"]+)" | search method="*Aura*" | stats count by method, src_ip, user
```
*Comment: This search identifies requests to Salesforce Aura methods, including `getConfigData`, `getItems`, and others, which could indicate potential misuse.*

### Detecting GraphQL API Usage
```spl
index=proxy sourcetype=bluecoat uri_path="*/graphql" | stats count by src_ip, user, uri_path
```
*Comment: This search identifies usage of the GraphQL API, which could be abused to bypass Salesforce record limits.*

### Detecting Bulk Actions via Boxcar'ing
```spl
index=proxy sourcetype=bluecoat uri_path="*/aura" http_method=POST | rex field=_raw "Content-Length: (?<content_length>\d+)" | where content_length > 100000 | stats count by src_ip, user, content_length
```
*Comment: This search identifies large POST requests to the Salesforce Aura endpoint, which may indicate abuse of the boxcar'ing mechanism.*

### Detecting Access to Home URLs
```spl
index=proxy sourcetype=bluecoat uri_path="*/recordlist/*" OR uri_path="*/s/recordlist/*" | stats count by src_ip, user, uri_path
```
*Comment: This search identifies access to Salesforce Record List URLs, which may indicate unauthorized access to sensitive data.*

### Detecting Self-Registration Abuse
```spl
index=proxy sourcetype=bluecoat uri_path="*/applauncher.LoginFormController/ACTION*" | stats count by src_ip, user, uri_path
```
*Comment: This search identifies requests to the `getIsSelfRegistrationEnabled` and `getSelfRegistrationUrl` methods, which could indicate attempts to exploit self-registration misconfigurations.*

## 6. Executive Summary

On January 12, 2026, Mandiant released a detailed report on Salesforce Aura framework misconfigurations, highlighting significant risks of unauthorized data access. The report introduces a new open-source tool, AuraInspector, designed to identify and audit these misconfigurations. Key techniques include exploiting Aura methods like `getConfigData` and `getItems`, abusing the GraphQL API to bypass Salesforce's 2,000-record limit, and leveraging misconfigured self-registration settings to create unauthorized accounts. Organizations using Salesforce Experience Cloud are advised to immediately review and secure their access control configurations, disable unnecessary endpoints, and monitor for suspicious activity using the provided detection searches.
