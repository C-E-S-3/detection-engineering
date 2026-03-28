---
scraped_at: 2026-01-12T00:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure/
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### Domains/URLs
- None identified.

### File Hashes
- None identified.

### IP Addresses
- None identified.

### Other IOCs
- None identified.

## 2. TTPs (MITRE ATT&CK Mapping)

### TTPs Identified
- **Tactic**: Collection
  - **Technique ID**: T1213.003
  - **Technique Name**: Data from Information Repositories: Sharepoint
  - **Description**: The Salesforce Aura framework was found to have misconfigurations that could allow unauthorized access to sensitive data, such as credit card numbers and identity documents, through its endpoints.

- **Tactic**: Collection
  - **Technique ID**: T1530
  - **Technique Name**: Data from Cloud Storage Object
  - **Description**: The Salesforce GraphQL API was found to allow retrieval of all records tied to an object, bypassing the 2,000 record limit, if access controls are misconfigured.

- **Tactic**: Initial Access
  - **Technique ID**: T1078
  - **Technique Name**: Valid Accounts
  - **Description**: Misconfigured self-registration settings in Salesforce could allow attackers to create authenticated accounts and gain unauthorized access to sensitive data.

## 3. Malware & Tools

### Tools
- **AuraInspector**: An open-source tool released by Mandiant to identify and audit access control misconfigurations within the Salesforce Aura framework.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor**: Not specified.
- **Campaign Name**: Not specified.
- **Motivations**: Likely financial gain or data theft, targeting sensitive information such as credit card numbers, identity documents, and health information.
- **Targeted Sectors/Geographies**: Organizations using Salesforce Experience Cloud.

## 5. Splunk Detection Searches

### Detecting Misconfigured Aura Endpoints
```spl
index=web sourcetype=access_combined
| search uri_path="/aura" AND request_method="POST"
| table _time, clientip, uri_path, http_user_agent, status, bytes
| where like(_raw, "%getConfigData%")
```
*This search identifies HTTP POST requests to the Salesforce Aura endpoint that include the `getConfigData` method, which could indicate an attempt to exploit access control misconfigurations.*

### Detecting GraphQL API Access
```spl
index=web sourcetype=access_combined
| search uri_path="/graphql" AND request_method="POST"
| table _time, clientip, uri_path, http_user_agent, status, bytes
```
*This search identifies HTTP POST requests to the Salesforce GraphQL API endpoint, which could indicate attempts to exploit misconfigured access controls.*

### Detecting Self-Registration Exploitation
```spl
index=web sourcetype=access_combined
| search uri_path="/self-registration" AND request_method="POST"
| table _time, clientip, uri_path, http_user_agent, status, bytes
```
*This search identifies HTTP POST requests to the self-registration endpoint, which could indicate unauthorized account creation attempts.*

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, to help organizations identify and audit access control misconfigurations in the Salesforce Aura framework. These misconfigurations could allow unauthorized access to sensitive data such as credit card numbers and identity documents. Additionally, the Salesforce GraphQL API was found to allow retrieval of all records tied to an object, bypassing the 2,000 record limit, if access controls are misconfigured. Organizations using Salesforce should immediately review their access control configurations, disable self-registration if not required, and monitor for suspicious activity on Salesforce endpoints using the provided Splunk detection searches.