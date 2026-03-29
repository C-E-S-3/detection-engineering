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

### Tactic: Collection
- **Technique ID**: T1530
  **Technique Name**: Data from Cloud Storage Object
  **Description**: The Salesforce Aura framework allows attackers to exploit misconfigured access controls to retrieve sensitive data such as credit card numbers, identity documents, and health information.

### Tactic: Collection
- **Technique ID**: T1530
  **Technique Name**: Data from Cloud Storage Object
  **Description**: The `getConfigData` Aura method can be used to retrieve a list of objects from the backend Salesforce database.

### Tactic: Collection
- **Technique ID**: T1530
  **Technique Name**: Data from Cloud Storage Object
  **Description**: The `getItems` Aura method can be used to retrieve records for specific objects, with the ability to bypass Salesforce's 2,000-record limit using the `sortBy` parameter.

### Tactic: Collection
- **Technique ID**: T1530
  **Technique Name**: Data from Cloud Storage Object
  **Description**: The `getInitialListViews` Aura method can be used to identify the presence of Record Lists, which may expose sensitive data if access controls are misconfigured.

### Tactic: Collection
- **Technique ID**: T1530
  **Technique Name**: Data from Cloud Storage Object
  **Description**: The `getAppBootstrapData` Aura method can be used to retrieve Home URLs, which may lead to sensitive administration or configuration panels.

### Tactic: Credential Access
- **Technique ID**: T1539
  **Technique Name**: Steal Web Session Cookie
  **Description**: The `getIsSelfRegistrationEnabled` and `getSelfRegistrationUrl` Aura methods can be used to identify if self-registration is enabled and retrieve the self-registration URL, potentially allowing attackers to create accounts and gain unauthorized access.

### Tactic: Collection
- **Technique ID**: T1530
  **Technique Name**: Data from Cloud Storage Object
  **Description**: The GraphQL Aura controller can be used to bypass the 2,000-record limit and retrieve all records tied to an object, provided the object is misconfigured.

## 3. Malware & Tools

- **AuraInspector**: An open-source command-line tool developed by Mandiant to identify and audit access control misconfigurations in Salesforce Aura.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor**: Not specified
- **Campaign Name**: Not specified
- **Motivations**: Exploitation of Salesforce Aura misconfigurations to gain unauthorized access to sensitive data, including credit card numbers, identity documents, and health information.
- **Targeted Sectors/Geographies**: Organizations using Salesforce Experience Cloud, particularly those with misconfigured access controls.

## 5. Splunk Detection Searches

### Detecting Misuse of `getConfigData` Aura Method
```spl
index=network sourcetype=http
| search "POST /aura" "serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData"
| stats count by src_ip, http_user_agent
| table src_ip, http_user_agent, count
```

### Detecting Misuse of `getItems` Aura Method
```spl
index=network sourcetype=http
| search "POST /aura" "serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems"
| stats count by src_ip, http_user_agent
| table src_ip, http_user_agent, count
```

### Detecting Misuse of `getInitialListViews` Aura Method
```spl
index=network sourcetype=http
| search "POST /aura" "serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews"
| stats count by src_ip, http_user_agent
| table src_ip, http_user_agent, count
```

### Detecting Misuse of `getAppBootstrapData` Aura Method
```spl
index=network sourcetype=http
| search "POST /aura" "serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData"
| stats count by src_ip, http_user_agent
| table src_ip, http_user_agent, count
```

### Detecting Misuse of GraphQL Aura Controller
```spl
index=network sourcetype=http
| search "POST /graphql" "GraphQL Aura controller"
| stats count by src_ip, http_user_agent
| table src_ip, http_user_agent, count
```

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, to identify and audit access control misconfigurations in Salesforce Aura. The report highlights several previously undocumented techniques, including the misuse of Aura methods (`getConfigData`, `getItems`, `getInitialListViews`, `getAppBootstrapData`) and the GraphQL Aura controller to exploit misconfigurations and retrieve sensitive data. These techniques can lead to unauthorized access to sensitive information such as credit card numbers, identity documents, and health information. Organizations using Salesforce Experience Cloud should immediately review their access control configurations and implement the recommended mitigations to secure their environments.