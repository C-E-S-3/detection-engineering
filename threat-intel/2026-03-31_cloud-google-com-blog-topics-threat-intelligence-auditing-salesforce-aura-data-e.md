---
scraped_at: 2026-01-12T00:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure/
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### Domains/URLs
- None identified.

### File Hashes
- None identified.

### IP Addresses
- None identified.

### Other IOCs
- Aura method calls:
  - `serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData`
  - `serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems`
  - `serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews`
  - `serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData`
  - `apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled`
  - `apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl`

## 2. TTPs (MITRE ATT&CK Mapping)

- **Tactic:** Collection
  - **Technique ID:** T1213.003
  - **Technique Name:** Data from Information Repositories: Cloud Storage
  - **Description:** Misconfigured Salesforce Aura endpoints allow unauthorized access to sensitive data, including credit card numbers and identity documents.

- **Tactic:** Discovery
  - **Technique ID:** T1087.002
  - **Technique Name:** Account Discovery: Domain Accounts
  - **Description:** Misconfigured Aura methods allow attackers to enumerate Salesforce objects and retrieve associated records.

- **Tactic:** Exfiltration
  - **Technique ID:** T1041
  - **Technique Name:** Exfiltration Over C2 Channel
  - **Description:** Exploited Aura methods can be used to exfiltrate large volumes of Salesforce records.

## 3. Malware & Tools

- **Tool Name:** AuraInspector
  - **Description:** Open-source tool released by Mandiant to identify and audit access control misconfigurations in Salesforce Aura framework.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor:** None explicitly identified.
- **Campaign:** None explicitly identified.
- **Targeted Sectors:** Organizations using Salesforce Experience Cloud, particularly those handling sensitive data such as credit card numbers, identity documents, and health information.

## 5. Splunk Detection Searches

### Detecting Unauthorized Aura Method Calls

#### Search for `serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData`
```spl
index=network sourcetype="http" uri_path="/serviceComponent" 
| search "ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData"
| stats count by src_ip, uri_path, http_user_agent
```

#### Detecting Unauthorized Access to Record Lists
```spl
index=network sourcetype="http" uri_path="/s/recordlist/"
| stats count by src_ip, uri_path, http_user_agent
```

#### Detecting Bulk Aura Requests
```spl
index=network sourcetype="http" uri_path="/serviceComponent" 
| search "actions" "descriptor" "callingDescriptor"
| stats count by src_ip, uri_path, http_user_agent
```

#### Detecting GraphQL API Misuse
```spl
index=network sourcetype="http" uri_path="/graphql"
| stats count by src_ip, uri_path, http_user_agent
```

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, to help organizations identify and mitigate access control misconfigurations in the Salesforce Aura framework. These misconfigurations can allow unauthorized access to sensitive data, including credit card numbers and identity documents. The report highlights several previously undocumented techniques, such as exploiting GraphQL APIs and Aura methods, to bypass Salesforce's record retrieval limits and access sensitive data. Organizations using Salesforce Experience Cloud are advised to review their access control configurations and implement the provided Splunk detection searches to monitor for potential misuse.