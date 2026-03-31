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
- **Aura Method:** `serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData` (used to retrieve backend Salesforce database objects)
- **Aura Method:** `serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems` (used to retrieve records for specific objects)
- **Aura Method:** `serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews` (used to check for Record Lists associated with objects)
- **Aura Method:** `serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData` (used to retrieve Home URLs for administration/configuration panels)
- **Aura Method:** `apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled` (used to check if self-registration is enabled)
- **Aura Method:** `apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl` (used to retrieve the self-registration URL)

## 2. TTPs (MITRE ATT&CK Mapping)

### Tactics and Techniques
- **T1078.003 - Valid Accounts: Local Accounts**
  - Exploiting misconfigured Salesforce access controls to gain unauthorized access to sensitive data.
- **T1210 - Exploitation of Remote Services**
  - Leveraging misconfigured Salesforce Aura endpoints to retrieve sensitive data.
- **T1530 - Data from Cloud Storage Object**
  - Using GraphQL API to bypass Salesforce record retrieval limits and access sensitive data.
- **T1071.001 - Application Layer Protocol: Web Protocols**
  - Abuse of Salesforce Aura methods and GraphQL API for unauthorized data retrieval.

## 3. Malware & Tools

### Tools
- **AuraInspector**
  - An open-source command-line tool released by Mandiant to identify and audit access control misconfigurations in Salesforce Aura.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor:** Not specified
- **Campaign Name:** Not specified
- **Motivations:** Likely financial gain through unauthorized access to sensitive data such as credit card numbers, identity documents, and health information.
- **Targeted Sectors/Geographies:** Organizations using Salesforce Experience Cloud.

## 5. Splunk Detection Searches

### Detecting Abuse of Aura Methods
```spl
index=network sourcetype="http_event" uri_path="/aura" 
| spath input=_raw output=actions
| search actions="serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData" OR \
        actions="serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems" OR \
        actions="serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews" OR \
        actions="serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData" OR \
        actions="apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled" OR \
        actions="apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl"
| stats count by actions, src_ip
```

### Detecting GraphQL API Abuse
```spl
index=network sourcetype="http_event" uri_path="/graphql" 
| spath input=_raw output=query
| search query="query" OR query="mutation"
| stats count by query, src_ip
```

## 6. Executive Summary

Mandiant has released a new open-source tool, AuraInspector, to identify and audit access control misconfigurations in Salesforce Aura. The report highlights several previously undocumented techniques, including abusing Aura methods and the GraphQL API to bypass Salesforce's record retrieval limits and access sensitive data. These misconfigurations could allow unauthorized users to retrieve sensitive information such as credit card numbers, identity documents, and health information. Organizations using Salesforce should immediately review and secure their Aura endpoints and access control configurations to mitigate these risks.