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

### Tactic: Collection (TA0009)
- **Technique ID**: T1530 - Data from Cloud Storage Object
  - **Description**: The Salesforce Aura framework's misconfigurations can allow unauthorized access to sensitive data, including credit card numbers, identity documents, and health information.

### Tactic: Discovery (TA0007)
- **Technique ID**: T1592 - Gather Victim Host Information
  - **Description**: Attackers can use the `getConfigData` Aura method to retrieve a list of objects in the backend Salesforce database.

### Tactic: Collection (TA0009)
- **Technique ID**: T1530 - Data from Cloud Storage Object
  - **Description**: The `getItems` Aura method can be used to retrieve records for specific objects, bypassing Salesforce's 2,000-record limit by leveraging the `sortBy` parameter.

### Tactic: Discovery (TA0007)
- **Technique ID**: T1592 - Gather Victim Host Information
  - **Description**: The `getInitialListViews` Aura method can reveal the presence of Record Lists, potentially exposing sensitive data if access controls are misconfigured.

### Tactic: Discovery (TA0007)
- **Technique ID**: T1592 - Gather Victim Host Information
  - **Description**: The `getAppBootstrapData` Aura method can expose administrative or configuration panel URLs for third-party Salesforce modules.

### Tactic: Credential Access (TA0006)
- **Technique ID**: T1078 - Valid Accounts
  - **Description**: The `getIsSelfRegistrationEnabled` and `getSelfRegistrationUrl` methods can reveal whether self-registration is enabled and provide the URL, potentially allowing attackers to create unauthorized accounts.

### Tactic: Collection (TA0009)
- **Technique ID**: T1530 - Data from Cloud Storage Object
  - **Description**: The GraphQL Aura controller can be used to bypass Salesforce's 2,000-record limit and retrieve all records tied to an object, provided the object permissions are misconfigured.

## 3. Malware & Tools

### Tools
- **AuraInspector**: An open-source command-line tool released by Mandiant to identify and audit access control misconfigurations and potential data exposures in the Salesforce Aura framework.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor**: None explicitly identified in the report.
- **Campaign Name**: None explicitly identified in the report.
- **Motivations**: Exploitation of Salesforce Aura framework misconfigurations to access sensitive data, including credit card numbers, identity documents, and health information.
- **Targeted Sectors/Geographies**: Organizations using Salesforce Experience Cloud, potentially across various sectors.

## 5. Splunk Detection Searches

### Detecting Misuse of Aura Methods

#### Detecting `getConfigData` Method Usage
```spl
index=network sourcetype="http:json" 
| spath input=_raw output=actions
| search actions{}.descriptor="serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData"
| table _time src_ip dest_ip actions{}.params
```

#### Detecting `getItems` Method with `sortBy` Parameter
```spl
index=network sourcetype="http:json" 
| spath input=_raw output=actions
| search actions{}.descriptor="serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems" actions{}.params.sortBy="*"
| table _time src_ip dest_ip actions{}.params
```

#### Detecting `getInitialListViews` Method Usage
```spl
index=network sourcetype="http:json" 
| spath input=_raw output=actions
| search actions{}.descriptor="serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews"
| table _time src_ip dest_ip actions{}.params
```

#### Detecting `getAppBootstrapData` Method Usage
```spl
index=network sourcetype="http:json" 
| spath input=_raw output=actions
| search actions{}.descriptor="serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData"
| table _time src_ip dest_ip actions{}.params
```

#### Detecting Self-Registration Methods Usage
```spl
index=network sourcetype="http:json" 
| spath input=_raw output=actions
| search actions{}.descriptor IN ("apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled", "apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl")
| table _time src_ip dest_ip actions{}.params
```

#### Detecting GraphQL Aura Controller Usage
```spl
index=network sourcetype="http:json" 
| spath input=_raw output=actions
| search actions{}.descriptor="serviceComponent://ui.force.components.controllers.graphql.GraphQLController/ACTION$query"
| table _time src_ip dest_ip actions{}.params
```

## 6. Executive Summary

On January 12, 2026, Mandiant released a detailed report on misconfigurations in the Salesforce Aura framework, which could allow unauthorized access to sensitive data such as credit card numbers, identity documents, and health information. The report highlights several techniques, including the misuse of Aura methods (`getConfigData`, `getItems`, `getInitialListViews`, `getAppBootstrapData`) and the GraphQL Aura controller to exploit access control gaps. Mandiant also introduced an open-source tool, AuraInspector, to help administrators identify and remediate these misconfigurations. Organizations using Salesforce Experience Cloud should immediately review their access control configurations and implement the provided Splunk detection searches to monitor for potential misuse of these methods.