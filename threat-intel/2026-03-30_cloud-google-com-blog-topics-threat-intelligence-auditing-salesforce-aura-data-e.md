---
scraped_at: 2026-01-12T00:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure/
report_type: threat-intel
---

# Threat Intelligence Report: Salesforce Aura Data Exposure

## 1. Indicators of Compromise (IOCs)
No specific IOCs (e.g., IPs, domains, hashes) were identified in the source content.

## 2. TTPs (MITRE ATT&CK Mapping)
- **Tactic: Initial Access**
  - **Technique ID:** T1190 (Exploit Public-Facing Application)
  - **Description:** Exploiting misconfigured Salesforce Aura endpoints to access sensitive data such as credit card numbers, identity documents, and health information.

- **Tactic: Collection**
  - **Technique ID:** T1213 (Data from Information Repositories)
  - **Description:** Using Salesforce Aura methods (e.g., `getConfigData`, `getItems`, `getInitialListViews`) to retrieve sensitive data from misconfigured Salesforce objects.

- **Tactic: Discovery**
  - **Technique ID:** T1087.002 (Account Discovery: Domain Accounts)
  - **Description:** Exploiting the `getIsSelfRegistrationEnabled` and `getSelfRegistrationUrl` methods to identify self-registration pages and URLs for unauthorized account creation.

- **Tactic: Collection**
  - **Technique ID:** T1530 (Data from Cloud Storage Object)
  - **Description:** Leveraging Salesforce GraphQL API to bypass the 2,000-record retrieval limit and access large datasets from misconfigured objects.

## 3. Malware & Tools
- **Tool:** AuraInspector
  - **Description:** Open-source command-line tool released by Mandiant to identify and audit access control misconfigurations in Salesforce Aura framework.

## 4. Threat Actor / Campaign Attribution
- **Attribution:** Not explicitly tied to a specific threat actor or campaign.
- **Motivation:** Likely cybercriminals or malicious insiders targeting sensitive data (e.g., credit card numbers, identity documents, health information) stored in Salesforce environments.
- **Targeted Sectors:** Organizations using Salesforce Experience Cloud, particularly those handling sensitive customer data.

## 5. Splunk Detection Searches

### Detecting Salesforce Aura Misconfigurations
```spl
index=proxy OR index=web
| search uri_path="*/serviceComponent://ui.force.components.controllers.*"
| stats count by uri_path, http_method, src_ip
| where count > 100
| table uri_path, http_method, src_ip, count
```
*Comment: This search identifies anomalous activity targeting Salesforce Aura endpoints by analyzing HTTP requests to specific URI paths.*

### Detecting GraphQL API Usage for Data Exfiltration
```spl
index=proxy OR index=web
| search uri_path="*/graphql" http_method=POST
| stats count by src_ip, uri_path, http_method
| where count > 50
| table src_ip, uri_path, count
```
*Comment: This search detects potential abuse of the Salesforce GraphQL API for data exfiltration by identifying high-frequency POST requests to GraphQL endpoints.*

### Detecting Self-Registration Page Access
```spl
index=proxy OR index=web
| search uri_path="*/self-registration" http_method=GET
| stats count by src_ip, uri_path
| where count > 10
| table src_ip, uri_path, count
```
*Comment: This search identifies repeated access attempts to self-registration pages, which could indicate reconnaissance or unauthorized account creation attempts.*

## 6. Executive Summary
Mandiant has released a new open-source tool, AuraInspector, to help organizations identify and remediate access control misconfigurations in Salesforce Aura. These misconfigurations can expose sensitive data, such as credit card numbers and identity documents, to unauthorized users. Attackers can exploit Salesforce Aura methods and the GraphQL API to bypass record retrieval limits and access sensitive data. Organizations using Salesforce should immediately review their access control configurations, disable self-registration if not required, and monitor for unauthorized access attempts to Salesforce endpoints using the provided Splunk detection searches.