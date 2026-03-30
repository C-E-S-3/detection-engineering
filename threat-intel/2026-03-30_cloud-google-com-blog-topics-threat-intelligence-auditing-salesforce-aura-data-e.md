---
scraped_at: 2026-01-12T00:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure/
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### IP Addresses
No new IP addresses identified.

### Domains/URLs
No new domains or URLs identified.

### File Hashes
No new file hashes identified.

### Other IOCs
- **Aura Endpoint**: `serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData`
  - Context: Used to retrieve a list of objects in the backend Salesforce database.
- **Aura Endpoint**: `serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems`
  - Context: Used to retrieve records for specific objects in Salesforce.
- **Aura Endpoint**: `serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews`
  - Context: Used to check if an object has an associated record list component.
- **Aura Endpoint**: `serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData`
  - Context: Used to retrieve home URLs for administration or configuration panels.
- **Aura Endpoint**: `apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled`
  - Context: Used to check if self-registration is enabled.
- **Aura Endpoint**: `apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl`
  - Context: Used to retrieve the self-registration URL.

## 2. TTPs (MITRE ATT&CK Mapping)

- **Tactic**: Initial Access
  - **Technique**: Exploit Public-Facing Application (T1190)
    - **Description**: Exploiting misconfigured Salesforce Aura endpoints to access sensitive data or administrative panels.

- **Tactic**: Collection
  - **Technique**: Data from Information Repositories (T1213)
    - **Description**: Using misconfigured Aura endpoints to retrieve sensitive records, including credit card numbers, identity documents, and health information.

- **Tactic**: Discovery
  - **Technique**: Application Window Discovery (T1010)
    - **Description**: Using the `getInitialListViews` Aura method to identify accessible record lists.

- **Tactic**: Credential Access
  - **Technique**: Account Discovery (T1087)
    - **Description**: Exploiting self-registration endpoints to create unauthorized accounts.

## 3. Malware & Tools

- **Tool**: AuraInspector
  - **Description**: Open-source command-line tool released by Mandiant to identify and audit access control misconfigurations in Salesforce Aura.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor**: Not specified.
- **Campaign Name**: Not specified.
- **Motivations**: Likely financial gain or data theft, targeting sensitive information such as credit card numbers, identity documents, and health information stored in Salesforce.
- **Targeted Sectors/Geographies**: Organizations using Salesforce Experience Cloud, potentially across multiple sectors.

## 5. Splunk Detection Searches

### Detecting Access to `getConfigData` Aura Endpoint
```spl
index=proxy OR index=web
| search uri_path="*/serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData"
| stats count by src_ip, user, uri_path
```

### Detecting Access to `getItems` Aura Endpoint
```spl
index=proxy OR index=web
| search uri_path="*/serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems"
| stats count by src_ip, user, uri_path
```

### Detecting Access to `getInitialListViews` Aura Endpoint
```spl
index=proxy OR index=web
| search uri_path="*/serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews"
| stats count by src_ip, user, uri_path
```

### Detecting Access to `getAppBootstrapData` Aura Endpoint
```spl
index=proxy OR index=web
| search uri_path="*/serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData"
| stats count by src_ip, user, uri_path
```

### Detecting Access to Self-Registration Endpoints
```spl
index=proxy OR index=web
| search uri_path="*/apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled" OR uri_path="*/apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl"
| stats count by src_ip, user, uri_path
```

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, to identify and audit access control misconfigurations in Salesforce Aura. These misconfigurations can expose sensitive data, such as credit card numbers and identity documents, to unauthorized users. The report highlights several previously undocumented techniques, including the use of GraphQL to bypass Salesforce's 2,000-record retrieval limit and the exploitation of misconfigured Aura endpoints to access sensitive data and administrative panels. Organizations using Salesforce Experience Cloud should immediately review their access control configurations, disable self-registration if not required, and monitor for unauthorized access to critical endpoints.