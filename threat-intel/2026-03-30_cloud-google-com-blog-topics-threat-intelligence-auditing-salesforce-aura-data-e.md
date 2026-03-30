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
- `serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews` (Aura method for identifying Record Lists)
- `serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData` (Aura method for retrieving Home URLs)
- `apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled` (Aura method for checking self-registration status)
- `apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl` (Aura method for retrieving self-registration URL)

## 2. TTPs (MITRE ATT&CK Mapping)

- **Tactic**: Initial Access  
  **Technique**: Exploit Public-Facing Application (T1190)  
  **Description**: Exploiting misconfigured Salesforce Aura endpoints to access sensitive data, including credit card numbers, identity documents, and health information.

- **Tactic**: Discovery  
  **Technique**: Application Window Discovery (T1010)  
  **Description**: Using the `getInitialListViews` Aura method to identify Record Lists and associated objects.

- **Tactic**: Collection  
  **Technique**: Data from Information Repositories (T1213)  
  **Description**: Leveraging the `getConfigData` and `getItems` Aura methods to retrieve sensitive data from Salesforce objects.

- **Tactic**: Collection  
  **Technique**: Automated Collection (T1119)  
  **Description**: Using the "boxcar'ing" mechanism to bulk multiple actions into a single request to retrieve large amounts of data.

- **Tactic**: Collection  
  **Technique**: Data from Information Repositories (T1213.003)  
  **Description**: Exploiting the GraphQL Aura controller to bypass Salesforce's 2,000-record retrieval limit and access all records tied to a misconfigured object.

## 3. Malware & Tools

- **AuraInspector**: An open-source tool developed by Mandiant to identify and audit access control misconfigurations in Salesforce Aura frameworks.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor**: Not specified
- **Campaign Name**: Not specified
- **Motivations**: Likely financial gain or data theft, targeting sensitive data such as credit card numbers, identity documents, and health information.
- **Targeted Sectors/Geographies**: Organizations using Salesforce Experience Cloud, particularly those with misconfigured access controls.

## 5. Splunk Detection Searches

### Detecting Misuse of Aura Methods

#### Search for `getConfigData` Method Usage
```spl
index=web sourcetype=access_combined
| search "serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData"
| stats count by clientip, uri, user
```

#### Search for `getItems` Method Usage
```spl
index=web sourcetype=access_combined
| search "serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems"
| stats count by clientip, uri, user
```

#### Search for `getInitialListViews` Method Usage
```spl
index=web sourcetype=access_combined
| search "serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews"
| stats count by clientip, uri, user
```

#### Search for `getAppBootstrapData` Method Usage
```spl
index=web sourcetype=access_combined
| search "serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData"
| stats count by clientip, uri, user
```

#### Search for Self-Registration Methods Usage
```spl
index=web sourcetype=access_combined
| search "apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled" OR "apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl"
| stats count by clientip, uri, user
```

### Detecting GraphQL API Usage
```spl
index=web sourcetype=access_combined
| search "GraphQL" "query" "mutation"
| stats count by clientip, uri, user
```

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, to identify and audit access control misconfigurations in Salesforce's Aura framework. The report highlights several new techniques, including the use of GraphQL to bypass Salesforce's 2,000-record retrieval limit, the exploitation of misconfigured Aura methods to access sensitive data, and the identification of misconfigured Record Lists and Home URLs. Organizations using Salesforce Experience Cloud should immediately review their access control configurations, disable unnecessary self-registration options, and monitor for unauthorized use of the identified Aura methods and GraphQL API. These techniques could be exploited by attackers to access sensitive data, posing a significant risk to organizations.