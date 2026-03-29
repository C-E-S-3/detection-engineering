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
- `serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData` (Aura method for retrieving backend Salesforce database object configurations)
- `serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems` (Aura method for retrieving records of specific objects)
- `serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews` (Aura method for identifying Record List components)
- `serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData` (Aura method for retrieving home URLs)
- `apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled` (Aura method for checking self-registration status)
- `apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl` (Aura method for retrieving self-registration URL)

## 2. TTPs (MITRE ATT&CK Mapping)

- **Tactic:** Collection
  - **Technique ID:** T1530 - Data from Cloud Storage Object
  - **Description:** Misconfigured Salesforce Aura endpoints allow unauthorized access to sensitive data, such as credit card numbers, identity documents, and health information.

- **Tactic:** Initial Access
  - **Technique ID:** T1078.003 - Valid Accounts: Cloud Accounts
  - **Description:** Exploiting misconfigured self-registration settings to gain unauthorized access to Salesforce instances.

- **Tactic:** Discovery
  - **Technique ID:** T1087.002 - Account Discovery: Domain Accounts
  - **Description:** Using Aura methods to retrieve information about user accounts and permissions.

- **Tactic:** Discovery
  - **Technique ID:** T1083 - File and Directory Discovery
  - **Description:** Using Aura methods to identify accessible Record List components and home URLs for potential exploitation.

- **Tactic:** Collection
  - **Technique ID:** T1530 - Data from Cloud Storage Object
  - **Description:** Leveraging GraphQL API to bypass Salesforce's 2,000-record retrieval limit and access additional records.

## 3. Malware & Tools

- **Tool:** AuraInspector
  - **Description:** An open-source command-line tool developed by Mandiant to identify and audit access control misconfigurations in Salesforce Aura framework.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor:** Not explicitly attributed to a specific threat actor.
- **Campaign Name:** Not specified.
- **Motivations:** Likely financial gain through unauthorized access to sensitive data such as credit card numbers, identity documents, and health information.
- **Targeted Sectors/Geographies:** Organizations using Salesforce Experience Cloud, potentially across various sectors.

## 5. Splunk Detection Searches

### Detecting Unauthorized Access to Aura Methods

```spl
index=proxy sourcetype=bluecoat
| search uri_path="/serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData"
| stats count by src_ip, uri_path
| table src_ip, uri_path, count
```
*# This search identifies access to the `getConfigData` Aura method, which could indicate attempts to exploit misconfigurations.*

### Detecting Bulk Record Retrieval via Aura Methods

```spl
index=proxy sourcetype=bluecoat
| search uri_path="/serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems"
| stats count by src_ip, uri_path
| table src_ip, uri_path, count
```
*# This search identifies potential bulk record retrieval attempts using the `getItems` Aura method.*

### Detecting Access to Home URLs

```spl
index=proxy sourcetype=bluecoat
| search uri_path="/serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData"
| stats count by src_ip, uri_path
| table src_ip, uri_path, count
```
*# This search identifies attempts to access home URLs via the `getAppBootstrapData` Aura method.*

### Detecting Self-Registration Status Checks

```spl
index=proxy sourcetype=bluecoat
| search uri_path="/apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled" OR uri_path="/apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl"
| stats count by src_ip, uri_path
| table src_ip, uri_path, count
```
*# This search identifies attempts to check self-registration status or retrieve self-registration URLs.*

### Detecting GraphQL API Usage

```spl
index=proxy sourcetype=bluecoat
| search uri_path="/graphql"
| stats count by src_ip, uri_path
| table src_ip, uri_path, count
```
*# This search identifies usage of the GraphQL API, which could be used to bypass record retrieval limits.*

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, to help identify and audit access control misconfigurations in the Salesforce Aura framework. These misconfigurations can allow unauthorized access to sensitive data, including credit card numbers and identity documents. Additionally, Mandiant has detailed a previously undocumented technique using the GraphQL API to bypass Salesforce's 2,000-record retrieval limit. Organizations using Salesforce Experience Cloud should immediately review their access control configurations, disable self-registration if not required, and monitor for unauthorized access to sensitive endpoints using the provided Splunk detection searches.