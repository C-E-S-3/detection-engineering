---
scraped_at: "2026-01-12T00:00:00Z"
source_url: "https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure/"
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### Domains/URLs
- None identified

### IP Addresses
- None identified

### File Hashes
- None identified

### Email Addresses
- None identified

### File Names/Paths
- None identified

### Registry Keys
- None identified

### Mutex Names
- None identified

### C2 Infrastructure
- None identified

## 2. TTPs (MITRE ATT&CK Mapping)

### Tactic: Credential Access
- **Technique ID**: T1552.003
  **Technique Name**: Steal Application Access Token
  **Description**: The Salesforce Aura framework's misconfigurations allow unauthorized users to retrieve sensitive data, such as credit card numbers and identity documents, by exploiting access control gaps.

### Tactic: Collection
- **Technique ID**: T1213
  **Technique Name**: Data from Information Repositories
  **Description**: Exploiting Salesforce Aura misconfigurations to retrieve sensitive data from Salesforce objects using legitimate Aura methods like `getConfigData` and `getItems`.

### Tactic: Discovery
- **Technique ID**: T1087.002
  **Technique Name**: Account Discovery: Domain Accounts
  **Description**: Using the `getIsSelfRegistrationEnabled` and `getSelfRegistrationUrl` Aura methods to identify self-registration status and URLs, potentially enabling attackers to create unauthorized accounts.

### Tactic: Collection
- **Technique ID**: T1530
  **Technique Name**: Data from Cloud Storage Object
  **Description**: Leveraging Salesforce GraphQL API to retrieve all records tied to misconfigured objects, bypassing the 2,000 record limit of standard Aura methods.

## 3. Malware & Tools

### Tools
- **AuraInspector**: An open-source command-line tool released by Mandiant to identify and audit access control misconfigurations in Salesforce Aura.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor**: Not explicitly mentioned.
- **Campaign Name**: Not explicitly mentioned.
- **Motivations**: Likely financial gain or data theft.
- **Targeted Sectors/Geographies**: Organizations using Salesforce Experience Cloud, potentially across various industries.

## 5. Splunk Detection Searches

### Detecting Unauthorized Access to Salesforce Aura Endpoints
```spl
index=proxy_logs sourcetype=bluecoat:proxysg
| search uri_path="/aura" AND http_method=POST
| table _time, src_ip, http_method, uri_path, http_user_agent, http_referrer
| rename src_ip as "Source IP", http_method as "HTTP Method", uri_path as "URI Path", http_user_agent as "User Agent", http_referrer as "Referrer"
```
*# This search identifies POST requests to Salesforce Aura endpoints, which could indicate potential unauthorized access attempts.*

### Detecting GraphQL API Usage
```spl
index=proxy_logs sourcetype=bluecoat:proxysg
| search uri_path="/graphql" AND http_method=POST
| table _time, src_ip, http_method, uri_path, http_user_agent, http_referrer
| rename src_ip as "Source IP", http_method as "HTTP Method", uri_path as "URI Path", http_user_agent as "User Agent", http_referrer as "Referrer"
```
*# This search identifies POST requests to the Salesforce GraphQL API, which could indicate attempts to retrieve large amounts of data.*

### Detecting Misconfigured Self-Registration Pages
```spl
index=proxy_logs sourcetype=bluecoat:proxysg
| search uri_path="/self-registration" AND http_method=GET
| table _time, src_ip, uri_path, http_user_agent, http_referrer
| rename src_ip as "Source IP", uri_path as "URI Path", http_user_agent as "User Agent", http_referrer as "Referrer"
```
*# This search identifies GET requests to Salesforce self-registration pages, which could indicate unauthorized access attempts.*

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, to help organizations identify and remediate access control misconfigurations in the Salesforce Aura framework. These misconfigurations can expose sensitive data, such as credit card numbers and identity documents, to unauthorized users. The report highlights new techniques, including the use of GraphQL APIs to bypass Salesforce's 2,000-record retrieval limit and the exploitation of self-registration pages to gain unauthorized access. Organizations using Salesforce Experience Cloud should immediately assess their configurations for potential vulnerabilities and leverage tools like AuraInspector to secure their environments.