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

- **Tactic: Initial Access**
  - **Technique ID: T1078**
  - **Technique Name: Valid Accounts**
  - **Description:** Exploiting misconfigured access controls in Salesforce Aura framework to gain unauthorized access to sensitive data, including credit card numbers, identity documents, and health information.

- **Tactic: Collection**
  - **Technique ID: T1213**
  - **Technique Name: Data from Information Repositories**
  - **Description:** Using Salesforce Aura methods such as `getConfigData` and `getItems` to retrieve sensitive data from Salesforce objects.

- **Tactic: Collection**
  - **Technique ID: T1530**
  - **Technique Name: Data from Cloud Storage Object**
  - **Description:** Leveraging the GraphQL API to bypass Salesforce’s 2,000-record retrieval limit and access all records tied to a misconfigured object.

- **Tactic: Discovery**
  - **Technique ID: T1087.002**
  - **Technique Name: Account Discovery: Domain Accounts**
  - **Description:** Using the `getIsSelfRegistrationEnabled` and `getSelfRegistrationUrl` methods to identify self-registration status and URLs for unauthorized access.

- **Tactic: Discovery**
  - **Technique ID: T1083**
  - **Technique Name: File and Directory Discovery**
  - **Description:** Using the `getAppBootstrapData` Aura method to retrieve administrative or configuration panel URLs for third-party Salesforce modules.

## 3. Malware & Tools

### Tools
- **AuraInspector**: An open-source command-line tool released by Mandiant to identify and audit access control misconfigurations and potential data exposures in Salesforce Aura framework.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor:** None explicitly identified in the source.
- **Campaign:** None explicitly identified in the source.
- **Motivations:** Likely financial gain through unauthorized access to sensitive data such as credit card numbers, identity documents, and health information.
- **Targeted Sectors/Geographies:** Organizations using Salesforce Experience Cloud, particularly those with misconfigured access controls.

## 5. Splunk Detection Searches

### Detecting Unauthorized Access to Salesforce Aura Methods
```spl
index=proxy sourcetype=bluecoat:proxysg
| search cs_uri_path="*/serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData"
| stats count by cs_username, cs_uri_path, cs_uri_query
| table cs_username, cs_uri_path, cs_uri_query, count
```
*Comment: This search identifies unauthorized access to the `getConfigData` Aura method.*

### Detecting GraphQL API Usage for Data Exfiltration
```spl
index=proxy sourcetype=bluecoat:proxysg
| search cs_uri_path="*/graphql"
| stats count by cs_username, cs_uri_path, cs_uri_query
| table cs_username, cs_uri_path, cs_uri_query, count
```
*Comment: This search identifies potential abuse of the GraphQL API for data exfiltration.*

### Detecting Self-Registration URL Access
```spl
index=proxy sourcetype=bluecoat:proxysg
| search cs_uri_path="*/applauncher.LoginFormController/ACTION$getSelfRegistrationUrl"
| stats count by cs_username, cs_uri_path, cs_uri_query
| table cs_username, cs_uri_path, cs_uri_query, count
```
*Comment: This search identifies attempts to access the self-registration URL using the `getSelfRegistrationUrl` Aura method.*

### Detecting Access to Administrative Panels via Home URLs
```spl
index=proxy sourcetype=bluecoat:proxysg
| search cs_uri_path="*/ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData"
| stats count by cs_username, cs_uri_path, cs_uri_query
| table cs_username, cs_uri_path, cs_uri_query, count
```
*Comment: This search identifies attempts to retrieve administrative or configuration panel URLs using the `getAppBootstrapData` Aura method.*

## 6. Executive Summary

On January 12, 2026, Mandiant released a new open-source tool called AuraInspector to identify and audit access control misconfigurations in Salesforce Aura framework. The report highlights several techniques to exploit these misconfigurations, including the use of GraphQL APIs to bypass Salesforce’s 2,000-record retrieval limit and retrieve sensitive data. Additionally, the report outlines methods to identify self-registration URLs and administrative panels that may be exposed due to misconfigurations. Organizations using Salesforce Experience Cloud are advised to review their access control configurations and implement the recommended mitigations to prevent unauthorized data access.