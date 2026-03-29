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
- `serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData` (Aura method for retrieving backend Salesforce database objects)
- `serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems` (Aura method for retrieving object records)
- `serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews` (Aura method for identifying Record List components)
- `serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData` (Aura method for retrieving Home URLs)
- `apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled` (Aura method for checking self-registration status)
- `apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl` (Aura method for retrieving self-registration URL)

## 2. TTPs (MITRE ATT&CK Mapping)

- **Tactic: Initial Access**
  - **Technique: Exploit Public-Facing Application (T1190)**
    - Exploitation of Salesforce Aura misconfigurations to access sensitive data such as credit card numbers, identity documents, and health information.

- **Tactic: Collection**
  - **Technique: Data from Information Repositories (T1213)**
    - Abuse of Salesforce Aura methods (e.g., `getConfigData`, `getItems`) to retrieve sensitive data from Salesforce objects.

- **Tactic: Discovery**
  - **Technique: Application Window Discovery (T1010)**
    - Use of Aura methods to identify accessible Record List components and Home URLs.

- **Tactic: Credential Access**
  - **Technique: Exploitation for Credential Access (T1212)**
    - Abuse of self-registration misconfigurations to gain unauthorized access to Salesforce instances.

## 3. Malware & Tools

- **AuraInspector**: An open-source tool released by Mandiant to identify and audit access control misconfigurations in Salesforce Aura.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor**: Not specified
- **Campaign Name**: Not specified
- **Motivations**: Likely financial gain through unauthorized access to sensitive data such as credit card numbers, identity documents, and health information.
- **Targeted Sectors/Geographies**: Organizations using Salesforce Experience Cloud, potentially across various sectors.

## 5. Splunk Detection Searches

### Detecting Usage of Specific Aura Methods

#### Search for `getConfigData` Method Usage
```spl
index=your_index sourcetype="your_sourcetype" 
| spath input=_raw output=actions
| search actions.descriptor="serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData"
| table _time, src_ip, user, actions
```

#### Search for `getItems` Method Usage
```spl
index=your_index sourcetype="your_sourcetype" 
| spath input=_raw output=actions
| search actions.descriptor="serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems"
| table _time, src_ip, user, actions
```

#### Search for `getInitialListViews` Method Usage
```spl
index=your_index sourcetype="your_sourcetype" 
| spath input=_raw output=actions
| search actions.descriptor="serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews"
| table _time, src_ip, user, actions
```

#### Search for `getAppBootstrapData` Method Usage
```spl
index=your_index sourcetype="your_sourcetype" 
| spath input=_raw output=actions
| search actions.descriptor="serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData"
| table _time, src_ip, user, actions
```

#### Search for Self-Registration Methods Usage
```spl
index=your_index sourcetype="your_sourcetype" 
| spath input=_raw output=actions
| search actions.descriptor IN ("apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled", "apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl")
| table _time, src_ip, user, actions
```

### Detecting GraphQL API Usage
```spl
index=your_index sourcetype="your_sourcetype" 
| spath input=_raw output=actions
| search actions.descriptor="GraphQL"
| table _time, src_ip, user, actions
```

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, to identify and audit access control misconfigurations in Salesforce Aura. The report highlights several previously undocumented techniques, including the abuse of Salesforce Aura methods and the GraphQL API, which can be exploited to bypass record retrieval limits and access sensitive data. Organizations using Salesforce Experience Cloud are advised to review their access control configurations, disable self-registration if not required, and monitor for unauthorized use of specific Aura methods and GraphQL queries. Immediate action is recommended to mitigate potential data exposure risks.