---
scraped_at: "2026-01-12T00:00:00Z"
source_url: "https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure/"
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
- `serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData` (Aura method for retrieving backend Salesforce database object configuration data)
- `serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems` (Aura method for retrieving object records)
- `serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews` (Aura method for identifying record list components)
- `serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData` (Aura method for retrieving home URLs)
- `apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled` (Aura method for checking self-registration status)
- `apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl` (Aura method for retrieving self-registration URL)

## 2. TTPs (MITRE ATT&CK Mapping)

- **Tactic: Initial Access**
  - **Technique ID: T1078.003** - Exploitation for Credential Access: Abuse of self-registration functionality to gain unauthorized access to Salesforce instances.
  - **Technique ID: T1190** - Exploit Public-Facing Application: Exploitation of misconfigured Salesforce Aura endpoints to access sensitive data.

- **Tactic: Collection**
  - **Technique ID: T1530** - Data from Cloud Storage Object: Exploiting Salesforce Aura misconfigurations to retrieve sensitive records, including credit card numbers, identity documents, and health information.
  - **Technique ID: T1074.001** - Data Staged: Using GraphQL API to bypass Salesforce's 2,000-record retrieval limit and collect large datasets.

- **Tactic: Discovery**
  - **Technique ID: T1087.002** - Account Discovery: Using the `getIsSelfRegistrationEnabled` and `getSelfRegistrationUrl` Aura methods to identify self-registration status and URLs.
  - **Technique ID: T1217** - Browser Bookmark Discovery: Retrieving home URLs via the `getAppBootstrapData` Aura method to locate administrative or configuration panels.

## 3. Malware & Tools

- **AuraInspector**: An open-source, command-line tool released by Mandiant to identify and audit access control misconfigurations in Salesforce Aura.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor**: No specific threat actor attribution provided.
- **Campaign Name**: Not specified.
- **Motivations**: Likely financial gain or data theft, targeting sensitive information such as credit card numbers, identity documents, and health information stored in Salesforce.
- **Targeted Sectors/Geographies**: Organizations using Salesforce, particularly those leveraging the Salesforce Aura framework and Experience Cloud.

## 5. Splunk Detection Searches

### Detecting Unauthorized Access to Aura Methods

```spl
index=proxy_logs
| search uri_path="/aura" AND (uri_query="*HostConfigController/ACTION$getConfigData*" OR uri_query="*SelectableListDataProviderController/ACTION$getItems*" OR uri_query="*ListViewPickerDataProviderController/ACTION$getInitialListViews*" OR uri_query="*CMCAppController/ACTION$getAppBootstrapData*" OR uri_query="*LoginFormController/ACTION$getIsSelfRegistrationEnabled*" OR uri_query="*LoginFormController/ACTION$getSelfRegistrationUrl*")
| stats count by uri_path, uri_query, src_ip
| table src_ip, uri_path, uri_query, count
```

*This search identifies unauthorized access attempts to specific Salesforce Aura methods.*

### Detecting GraphQL API Usage

```spl
index=proxy_logs
| search uri_path="/graphql" AND http_method="POST"
| stats count by src_ip, uri_path, http_method, user_agent
| table src_ip, uri_path, http_method, user_agent, count
```

*This search detects usage of the GraphQL API, which may indicate attempts to exploit misconfigurations for data exfiltration.*

### Detecting Bulked Aura Actions

```spl
index=proxy_logs
| search uri_path="/aura" AND http_method="POST" AND content_length>100000
| stats count by src_ip, uri_path, content_length
| table src_ip, uri_path, content_length, count
```

*This search identifies large POST requests to the Aura endpoint, which may indicate attempts to bulk actions for data retrieval.*

## 6. Executive Summary

On January 12, 2026, Mandiant released a report detailing common misconfigurations in Salesforce's Aura framework that can lead to unauthorized data access. These misconfigurations allow attackers to exploit legitimate Aura methods and the GraphQL API to bypass access controls and retrieve sensitive data, such as credit card numbers and identity documents. Mandiant also introduced AuraInspector, an open-source tool to help administrators identify and remediate these vulnerabilities. Organizations using Salesforce should immediately review their access control configurations, monitor for unauthorized access to critical endpoints, and consider leveraging tools like AuraInspector to identify and mitigate risks.