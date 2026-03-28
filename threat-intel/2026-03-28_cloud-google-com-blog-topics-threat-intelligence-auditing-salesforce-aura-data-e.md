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
- **Aura Method**: `serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData` (Context: Retrieves a list of objects used in the backend Salesforce database)
- **Aura Method**: `serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems` (Context: Retrieves records for a specific object in Salesforce Experience Cloud applications)
- **Aura Method**: `serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews` (Context: Checks if an object has an associated record list component)
- **Aura Method**: `serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData` (Context: Retrieves home URLs for administration or configuration panels in Salesforce)
- **Aura Method**: `apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled` (Context: Checks if self-registration is enabled for Salesforce instances)
- **Aura Method**: `apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl` (Context: Retrieves the self-registration URL for Salesforce instances)

## 2. TTPs (MITRE ATT&CK Mapping)

- **Tactic**: Initial Access
  - **Technique**: Exploit Public-Facing Application (T1190)
    - **Description**: Exploiting misconfigured Salesforce Aura endpoints to gain unauthorized access to sensitive data.

- **Tactic**: Collection
  - **Technique**: Automated Collection (T1119)
    - **Description**: Using the Aura framework's `getItems` method to retrieve large volumes of data, bypassing the 2,000-record limit with sorting parameters.

- **Tactic**: Discovery
  - **Technique**: Application Window Discovery (T1010)
    - **Description**: Using the `getInitialListViews` method to identify accessible Record List components in Salesforce.

- **Tactic**: Discovery
  - **Technique**: Application Layer Protocol (T1071)
    - **Description**: Leveraging the GraphQL Aura controller to retrieve records and metadata from Salesforce objects.

- **Tactic**: Credential Access
  - **Technique**: Account Discovery (T1087)
    - **Description**: Using the `getIsSelfRegistrationEnabled` and `getSelfRegistrationUrl` methods to identify and exploit self-registration functionality.

## 3. Malware & Tools

- **Tool**: AuraInspector
  - **Description**: An open-source command-line tool released by Mandiant to identify and audit access control misconfigurations in the Salesforce Aura framework.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor**: Not explicitly attributed to a specific threat actor.
- **Campaign**: No specific campaign identified.
- **Motivations**: Likely financial gain through unauthorized access to sensitive data such as credit card numbers, identity documents, and health information.
- **Targeted Sectors/Geographies**: Organizations using Salesforce Experience Cloud, potentially across various sectors.

## 5. Splunk Detection Searches

### Detecting Unauthorized Use of Aura Methods

```spl
index=network sourcetype="http:json" 
| spath input=_raw output=actions
| search actions{}.descriptor IN ("serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData", "serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems", "serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews", "serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData", "apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled", "apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl")
| table _time, src_ip, dest_ip, actions{}
```

### Detecting GraphQL API Usage

```spl
index=network sourcetype="http:json" 
| spath input=_raw output=actions
| search actions{}.descriptor="GraphQL"
| table _time, src_ip, dest_ip, actions{}
```

### Detecting Bulked Aura Actions

```spl
index=network sourcetype="http:json" 
| spath input=_raw output=actions
| search actions{}.id IN ("UserFavorite", "ProcessInstanceNode")
| stats count by src_ip, dest_ip, actions{}
| where count > 100
```

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, designed to identify and audit access control misconfigurations in Salesforce's Aura framework. The report highlights several new techniques, including leveraging GraphQL to bypass Salesforce's 2,000-record retrieval limit and exploiting misconfigured Aura methods to access sensitive data. Organizations using Salesforce Experience Cloud should immediately audit their configurations, restrict access to sensitive endpoints, and monitor for unauthorized use of Aura methods. The release of AuraInspector provides administrators with a valuable tool to secure their environments.