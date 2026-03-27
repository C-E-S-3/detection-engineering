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
- `serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData`: Aura method used to retrieve backend Salesforce database object configurations.
- `serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems`: Aura method used to retrieve object records with sorting and pagination.
- `serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews`: Aura method used to check for the presence of record list components.
- `serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData`: Aura method used to retrieve home URLs for administration or configuration panels.
- `apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled`: Aura method used to check if self-registration is enabled.
- `apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl`: Aura method used to retrieve the self-registration URL.

## 2. TTPs (MITRE ATT&CK Mapping)

### Tactics and Techniques
- **T1190 - Exploit Public-Facing Application**: Exploiting misconfigured Salesforce Aura endpoints to gain unauthorized access to sensitive data.
- **T1530 - Data from Cloud Storage Object**: Exploiting misconfigured access controls to retrieve sensitive data from Salesforce objects.
- **T1071.001 - Application Layer Protocol: Web Protocols**: Abuse of Salesforce Aura and GraphQL APIs to exfiltrate data.
- **T1005 - Data from Local System**: Retrieving sensitive records from Salesforce objects using misconfigured Aura methods.

## 3. Malware & Tools

### Tools
- **AuraInspector**: An open-source tool developed by Mandiant to identify and audit access control misconfigurations in Salesforce Aura framework.

## 4. Threat Actor / Campaign Attribution
- No specific threat actor or campaign attribution was mentioned in the source.

## 5. Splunk Detection Searches

### Detecting Misuse of Aura Methods

#### Detecting `getConfigData` Method Usage
```spl
index=proxy OR index=web
| search uri_path="*serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData*"
| stats count by src_ip, user, uri_path
| table src_ip, user, uri_path, count
```

#### Detecting `getItems` Method Usage
```spl
index=proxy OR index=web
| search uri_path="*serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems*"
| stats count by src_ip, user, uri_path
| table src_ip, user, uri_path, count
```

#### Detecting `getInitialListViews` Method Usage
```spl
index=proxy OR index=web
| search uri_path="*serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews*"
| stats count by src_ip, user, uri_path
| table src_ip, user, uri_path, count
```

#### Detecting `getAppBootstrapData` Method Usage
```spl
index=proxy OR index=web
| search uri_path="*serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData*"
| stats count by src_ip, user, uri_path
| table src_ip, user, uri_path, count
```

#### Detecting Self-Registration Methods Usage
```spl
index=proxy OR index=web
| search uri_path="*apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled*" OR uri_path="*apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl*"
| stats count by src_ip, user, uri_path
| table src_ip, user, uri_path, count
```

## 6. Executive Summary

Mandiant has released a new open-source tool called AuraInspector to identify and audit access control misconfigurations in Salesforce's Aura framework. The report highlights several previously undocumented techniques, including the use of GraphQL to bypass Salesforce's 2,000-record retrieval limit and the exploitation of misconfigured Aura methods to access sensitive data. These techniques could allow attackers to retrieve sensitive information such as credit card numbers, identity documents, and health information. Organizations using Salesforce should immediately review their access control configurations, disable self-registration if not required, and monitor for unauthorized use of the identified Aura methods.