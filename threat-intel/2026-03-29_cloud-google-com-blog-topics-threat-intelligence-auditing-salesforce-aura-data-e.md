---
scraped_at: 2026-01-12T00:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure/
report_type: threat-intel
---

# Threat Intelligence Report: Auditing Salesforce Aura for Data Exposure

## 1. Indicators of Compromise (IOCs)

### Domains/URLs
- None identified

### File Hashes
- None identified

### IP Addresses
- None identified

### Other IOCs
- **Aura Method**: `serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData`
  - **Context**: Used to retrieve a list of objects from the backend Salesforce database.
- **Aura Method**: `serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems`
  - **Context**: Used to retrieve records for a specific object, with the ability to bypass Salesforce's 2,000-record limit using the `sortBy` parameter.
- **Aura Method**: `serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews`
  - **Context**: Used to check if an object has an associated Record List component.
- **Aura Method**: `serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData`
  - **Context**: Used to retrieve a list of Home URLs, which may include administrative or configuration panels.
- **Aura Methods**: `apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled` and `apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl`
  - **Context**: Used to check if self-registration is enabled and retrieve the self-registration URL.

## 2. TTPs (MITRE ATT&CK Mapping)

- **Tactic**: Initial Access
  - **Technique ID**: T1078.003 (Valid Accounts: Local Accounts)
    - **Description**: Exploiting misconfigured Salesforce self-registration to gain unauthorized access to accounts.

- **Tactic**: Collection
  - **Technique ID**: T1530 (Data from Cloud Storage Object)
    - **Description**: Exploiting Salesforce Aura misconfigurations to retrieve sensitive data, such as credit card numbers, identity documents, and health information.

- **Tactic**: Discovery
  - **Technique ID**: T1087.002 (Account Discovery: Domain Accounts)
    - **Description**: Using Salesforce Aura methods to enumerate user accounts and associated data.

- **Tactic**: Data Exfiltration
  - **Technique ID**: T1020 (Automated Exfiltration)
    - **Description**: Using Salesforce Aura methods and GraphQL to retrieve and exfiltrate large volumes of data, bypassing record retrieval limits.

## 3. Malware & Tools

- **Tool**: AuraInspector
  - **Description**: An open-source command-line tool developed by Mandiant to identify and audit access control misconfigurations in the Salesforce Aura framework.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor**: Not explicitly attributed to a specific group.
- **Campaign Name**: Not specified.
- **Motivations**: Likely financial gain through unauthorized access to sensitive data, including credit card numbers, identity documents, and health information.
- **Targeted Sectors/Geographies**: Organizations using Salesforce Experience Cloud, particularly those with misconfigured access controls.

## 5. Splunk Detection Searches

### Detecting Unauthorized Access to Aura Methods
```spl
index=network sourcetype="http:json" 
| spath input=_raw output=actions
| search actions{}.descriptor IN ("serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData", 
                                  "serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems", 
                                  "serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews", 
                                  "serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData", 
                                  "apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled", 
                                  "apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl")
| table _time, src_ip, actions{}.descriptor, actions{}.params
```
*This search detects network traffic containing requests to the identified Salesforce Aura methods.*

### Detecting Large Data Exfiltration via GraphQL
```spl
index=network sourcetype="http:json" uri_path="/services/data/v*/graphql"
| spath input=_raw output=query
| search query="*"
| stats count by src_ip, uri_path, query
| where count > 2000
```
*This search identifies potential data exfiltration attempts using the GraphQL API to retrieve large volumes of records.*

### Detecting Self-Registration Exploitation
```spl
index=network sourcetype="http:json" uri_path="/apex/LoginFormController/ACTION$getSelfRegistrationUrl"
| stats count by src_ip, uri_path
| where count > 1
```
*This search identifies repeated attempts to access the self-registration URL, which may indicate exploitation.*

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, to help organizations identify and audit access control misconfigurations in Salesforce Aura. These misconfigurations can expose sensitive data, such as credit card numbers and identity documents, to unauthorized users. The report highlights a previously undocumented technique using GraphQL to bypass Salesforce's 2,000-record retrieval limit, as well as methods to identify misconfigured objects and administrative URLs. Organizations using Salesforce Experience Cloud should immediately review their access control configurations and implement the recommended mitigations to prevent unauthorized data access.