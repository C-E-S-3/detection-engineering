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
- `serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData` (Aura method for retrieving backend Salesforce database objects)
- `serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems` (Aura method for retrieving object records with sorting capabilities)
- `serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews` (Aura method for identifying Record List components)
- `serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData` (Aura method for retrieving home URLs)
- `apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled` (Aura method for checking self-registration status)
- `apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl` (Aura method for retrieving self-registration URL)

## 2. TTPs (MITRE ATT&CK Mapping)

### Tactic: Initial Access
- **T1190 - Exploit Public-Facing Application**: Exploiting misconfigured Salesforce Aura endpoints to gain unauthorized access to sensitive data.

### Tactic: Discovery
- **T1087 - Account Discovery**: Using the `getIsSelfRegistrationEnabled` and `getSelfRegistrationUrl` methods to identify self-registration status and URLs.
- **T1213 - Data from Information Repositories**: Using GraphQL API and Aura methods to retrieve sensitive data from Salesforce objects.

### Tactic: Collection
- **T1530 - Data from Cloud Storage Object**: Exploiting misconfigured Salesforce Aura endpoints to retrieve sensitive data such as credit card numbers, identity documents, and health information.

### Tactic: Defense Evasion
- **T1070.004 - File Deletion**: Potential for attackers to use Salesforce's "boxcar'ing" mechanism to bundle multiple actions into a single request, potentially evading detection.

## 3. Malware & Tools

- **AuraInspector**: An open-source tool released by Mandiant to identify and audit access control misconfigurations in Salesforce Aura.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor**: Not specified.
- **Campaign Name**: Not specified.
- **Motivations**: Likely financial gain through unauthorized access to sensitive data such as credit card numbers, identity documents, and health information.
- **Targeted Sectors/Geographies**: Organizations using Salesforce Experience Cloud, particularly those handling sensitive data.

## 5. Splunk Detection Searches

### Detecting Unauthorized Access to Aura Methods
```spl
index=web sourcetype=access_combined
| search "POST /aura" "serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData"
| stats count by clientip, uri, user
| table clientip, uri, user, count
```

### Detecting Bulk Actions in Salesforce Aura
```spl
index=web sourcetype=access_combined
| search "POST /aura" "actions" "id" "descriptor"
| rex field=_raw "\"actions\":\[(?<actions>.*?)\]"
| eval action_count=mvcount(split(actions, "{"))
| where action_count > 100
| table _time, clientip, action_count
```

### Detecting GraphQL API Usage
```spl
index=web sourcetype=access_combined
| search "POST /services/data/vXX.X/graphql"
| stats count by clientip, uri, user
| table clientip, uri, user, count
```

### Detecting Self-Registration Enumeration
```spl
index=web sourcetype=access_combined
| search "POST /aura" "apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled"
| stats count by clientip, uri, user
| table clientip, uri, user, count
```

## 6. Executive Summary

On January 12, 2026, Mandiant released a new open-source tool, AuraInspector, to identify and audit access control misconfigurations in Salesforce's Aura framework. The report highlights several new techniques, including the use of GraphQL APIs and Aura methods, to exploit misconfigurations in Salesforce Experience Cloud applications. These techniques can allow unauthorized access to sensitive data, such as credit card numbers and identity documents, and bypass Salesforce's 2,000-record retrieval limit. Organizations using Salesforce should immediately review their access control configurations and consider using tools like AuraInspector to identify and mitigate potential vulnerabilities.