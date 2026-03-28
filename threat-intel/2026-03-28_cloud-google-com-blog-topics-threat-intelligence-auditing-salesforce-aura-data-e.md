---
scraped_at: "2026-01-12T00:00:00Z"
source_url: "https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure/"
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### IP Addresses
- None identified

### Domains/URLs
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

### Tactic: Collection
- **Technique ID:** T1530 - Data from Cloud Storage Object
  - **Description:** The report highlights the use of Salesforce Aura misconfigurations to access sensitive data such as credit card numbers, identity documents, and health information stored in Salesforce objects.

### Tactic: Discovery
- **Technique ID:** T1087.002 - Account Discovery: Domain Account
  - **Description:** The report describes the use of Salesforce Aura methods to retrieve sensitive account information, including the `getConfigData` and `getItems` methods.

### Tactic: Collection
- **Technique ID:** T1074.001 - Data Staged: Local Data Staging
  - **Description:** The use of the `sortBy` parameter in Aura methods to bypass Salesforce’s 2,000-record retrieval limit and retrieve additional records.

### Tactic: Discovery
- **Technique ID:** T1592 - Gather Victim Host Information
  - **Description:** The use of GraphQL API for standardized retrieval of records, field names, and object information, including built-in introspection capabilities.

### Tactic: Credential Access
- **Technique ID:** T1078.003 - Valid Accounts: Cloud Accounts
  - **Description:** The report discusses the exploitation of Salesforce self-registration misconfigurations to gain unauthorized access to Salesforce instances.

## 3. Malware & Tools

### Tools
- **AuraInspector:** An open-source tool developed by Mandiant to identify and audit access control misconfigurations in Salesforce Aura.

## 4. Threat Actor / Campaign Attribution
- **Threat Actor:** Not explicitly attributed to a specific threat actor.
- **Campaign Name:** Not specified.
- **Motivations:** Likely financial gain or data theft, targeting sensitive information such as credit card numbers, identity documents, and health information.
- **Targeted Sectors/Geographies:** Organizations using Salesforce Experience Cloud, potentially across various sectors.

## 5. Splunk Detection Searches

### Detecting Misuse of Aura Methods
```spl
index=proxy_logs sourcetype=bluecoat:proxysg
| search uri_path="/aura" AND http_method="POST"
| spath input=_raw output=actions path="actions{}"
| mvexpand actions
| spath input=actions output=descriptor path="descriptor"
| search descriptor IN ("serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData", "serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems", "serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews", "serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData")
| table _time, src_ip, uri_path, descriptor, actions
```

### Detecting GraphQL API Usage
```spl
index=proxy_logs sourcetype=bluecoat:proxysg
| search uri_path="/graphql" AND http_method="POST"
| spath input=_raw output=query path="query"
| table _time, src_ip, uri_path, query
```

### Detecting Self-Registration Abuse
```spl
index=proxy_logs sourcetype=bluecoat:proxysg
| search uri_path="/applauncher.LoginFormController/ACTION$getSelfRegistrationUrl" OR uri_path="/applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled"
| table _time, src_ip, uri_path
```

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, to identify and audit access control misconfigurations in Salesforce Aura, a framework used in Salesforce applications. The report highlights several techniques that could be exploited by attackers to access sensitive data, including the use of GraphQL APIs and misconfigured Aura methods. These techniques can bypass Salesforce’s record retrieval limits and expose sensitive data such as credit card numbers and identity documents. Organizations using Salesforce Experience Cloud are advised to immediately review their access control configurations and implement recommended security measures to mitigate potential risks.