---
scraped_at: "2026-01-12T00:00:00Z"
source_url: "https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure/"
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)
No specific IOCs (e.g., IPs, domains, hashes) were identified in the source.

## 2. TTPs (MITRE ATT&CK Mapping)

### Tactic: Collection
- **Technique ID**: T1213.001
  **Technique Name**: Data from Information Repositories: Sharepoint
  **Description**: The Salesforce Aura framework's misconfigurations allow unauthorized users to access sensitive data, such as credit card numbers, identity documents, and health information, by exploiting access control gaps.

### Tactic: Collection
- **Technique ID**: T1530
  **Technique Name**: Data from Cloud Storage Object
  **Description**: Misconfigured Salesforce Aura endpoints can allow attackers to retrieve sensitive data stored in Salesforce objects, such as Account records, using methods like `getConfigData` and `getItems`.

### Tactic: Collection
- **Technique ID**: T1530
  **Technique Name**: Data from Cloud Storage Object
  **Description**: Attackers can exploit the `sortBy` parameter in the `getItems` Aura method to bypass Salesforce's 2,000-record retrieval limit and access additional records.

### Tactic: Discovery
- **Technique ID**: T1087
  **Technique Name**: Account Discovery
  **Description**: The `getIsSelfRegistrationEnabled` and `getSelfRegistrationUrl` methods in Salesforce can be used to identify whether self-registration is enabled and to retrieve the self-registration URL, which could allow attackers to create unauthorized accounts.

### Tactic: Discovery
- **Technique ID**: T1592
  **Technique Name**: Gather Victim Host Information
  **Description**: The `getAppBootstrapData` Aura method can be used to retrieve administrative or configuration panel URLs for third-party Salesforce modules, potentially exposing sensitive information.

### Tactic: Collection
- **Technique ID**: T1530
  **Technique Name**: Data from Cloud Storage Object
  **Description**: The Salesforce GraphQL API can be exploited to retrieve more than 2,000 records from misconfigured objects, bypassing standard record retrieval limits.

## 3. Malware & Tools
- **Tool Name**: AuraInspector
  **Description**: An open-source command-line tool developed by Mandiant to identify and audit access control misconfigurations within the Salesforce Aura framework. It automates the detection of data exposures and provides actionable remediation insights.

## 4. Threat Actor / Campaign Attribution
- **Threat Actor**: Not specified
- **Campaign Name**: Not specified
- **Motivations**: Likely to exploit misconfigurations in Salesforce Aura to gain unauthorized access to sensitive data, including credit card numbers, identity documents, and health information.
- **Targeted Sectors/Geographies**: Organizations using Salesforce Experience Cloud, potentially across various industries.

## 5. Splunk Detection Searches

### Detecting Misuse of `getConfigData` Aura Method
```spl
index=proxy_logs
| search uri_path="/aura" http_method="POST"
| spath input=_raw output=actions path=actions{}
| mvexpand actions
| spath input=actions output=descriptor path=descriptor
| search descriptor="serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData"
| stats count by src_ip, uri_path, descriptor
| rename src_ip as "Source IP", descriptor as "Aura Method"
```

### Detecting Misuse of `getItems` Aura Method
```spl
index=proxy_logs
| search uri_path="/aura" http_method="POST"
| spath input=_raw output=actions path=actions{}
| mvexpand actions
| spath input=actions output=descriptor path=descriptor
| search descriptor="serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems"
| stats count by src_ip, uri_path, descriptor
| rename src_ip as "Source IP", descriptor as "Aura Method"
```

### Detecting Misuse of `getAppBootstrapData` Aura Method
```spl
index=proxy_logs
| search uri_path="/aura" http_method="POST"
| spath input=_raw output=actions path=actions{}
| mvexpand actions
| spath input=actions output=descriptor path=descriptor
| search descriptor="serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData"
| stats count by src_ip, uri_path, descriptor
| rename src_ip as "Source IP", descriptor as "Aura Method"
```

### Detecting Misuse of GraphQL API
```spl
index=proxy_logs
| search uri_path="/services/data/vXX.X/graphql" http_method="POST"
| spath input=_raw output=query path=query
| search query="query"
| stats count by src_ip, uri_path
| rename src_ip as "Source IP", uri_path as "GraphQL Endpoint"
```

## 6. Executive Summary
Mandiant has released a new open-source tool, AuraInspector, to help organizations identify and remediate access control misconfigurations in Salesforce's Aura framework. These misconfigurations can expose sensitive data, such as credit card numbers and identity documents, to unauthorized users. Attackers can exploit methods like `getConfigData` and `getItems` to retrieve sensitive records, bypassing Salesforce's 2,000-record limit using sorting parameters. Additionally, the Salesforce GraphQL API can be abused to retrieve all records tied to misconfigured objects. Organizations using Salesforce should immediately review their access control configurations, disable self-registration if not required, and monitor for unauthorized use of the identified methods using the provided Splunk detection searches.
