---
scraped_at: 2026-01-12T00:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure/
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### IP Addresses
- None identified

### Domains/URLs
- None identified

### File Hashes
- None identified

### Email Addresses
- None identified

### File Names/Paths
- None identified

### Registry Keys
- None identified

### Mutex Names
- None identified

### C2 Infrastructure
- None identified

## 2. TTPs (MITRE ATT&CK Mapping)

### Tactic: Collection (TA0009)
- **Technique ID**: T1530 - Data from Cloud Storage Object
  - **Description**: The Salesforce Aura framework's misconfigurations allow unauthorized users to access sensitive data, such as credit card numbers, identity documents, and health information, through the `getConfigData` and `getItems` Aura methods.

### Tactic: Discovery (TA0007)
- **Technique ID**: T1087.002 - Account Discovery: Domain Account
  - **Description**: Misconfigured access controls allow attackers to retrieve records of the Account object, including sensitive information, using the `getItems` Aura method.

### Tactic: Collection (TA0009)
- **Technique ID**: T1213 - Data from Information Repositories
  - **Description**: Exploiting the GraphQL Aura controller to retrieve more than 2,000 records from Salesforce objects, bypassing standard record retrieval limits.

### Tactic: Discovery (TA0007)
- **Technique ID**: T1083 - File and Directory Discovery
  - **Description**: Using the `getAppBootstrapData` Aura method to retrieve home URLs that may expose sensitive administrative or configuration panels.

### Tactic: Initial Access (TA0001)
- **Technique ID**: T1078 - Valid Accounts
  - **Description**: Exploiting misconfigured self-registration settings to gain unauthorized access to Salesforce instances.

## 3. Malware & Tools

### Tools
- **AuraInspector**: An open-source command-line tool developed by Mandiant to identify and audit access control misconfigurations in Salesforce Aura.

## 4. Threat Actor / Campaign Attribution
- **Threat Actor**: Not specified
- **Campaign Name**: Not specified
- **Motivations**: Likely financial gain or data theft, targeting sensitive information such as credit card numbers, identity documents, and health information.
- **Targeted Sectors/Geographies**: Organizations using Salesforce Experience Cloud, potentially across various sectors.

## 5. Splunk Detection Searches

### Detecting Misuse of `getConfigData` Aura Method
```spl
index=network sourcetype="http" uri_path="/services/data/vXX.X/sobjects" method=POST
| spath input=_raw output=actions path="actions{}"
| search actions.descriptor="serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData"
| table _time src_ip dest_ip uri_path actions.params
```

### Detecting Misuse of `getItems` Aura Method
```spl
index=network sourcetype="http" uri_path="/services/data/vXX.X/sobjects" method=POST
| spath input=_raw output=actions path="actions{}"
| search actions.descriptor="serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems"
| table _time src_ip dest_ip uri_path actions.params
```

### Detecting Misuse of `getAppBootstrapData` Aura Method
```spl
index=network sourcetype="http" uri_path="/services/data/vXX.X/sobjects" method=POST
| spath input=_raw output=actions path="actions{}"
| search actions.descriptor="serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData"
| table _time src_ip dest_ip uri_path actions.params
```

### Detecting Misuse of Self-Registration Methods
```spl
index=network sourcetype="http" uri_path="/services/data/vXX.X/sobjects" method=POST
| spath input=_raw output=actions path="actions{}"
| search actions.descriptor IN ("apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled", "apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl")
| table _time src_ip dest_ip uri_path actions.params
```

### Detecting GraphQL API Misuse
```spl
index=network sourcetype="http" uri_path="/services/data/vXX.X/graphql" method=POST
| spath input=_raw output=query path="query"
| search query="*"
| table _time src_ip dest_ip uri_path query
```

## 6. Executive Summary

On January 12, 2026, Mandiant released a new open-source tool called AuraInspector to help organizations identify and mitigate access control misconfigurations in Salesforce's Aura framework. The report highlights several new techniques that attackers can exploit, including the misuse of Aura methods (`getConfigData`, `getItems`, `getAppBootstrapData`) and the GraphQL API to bypass record retrieval limits and access sensitive data. These techniques exploit misconfigurations in Salesforce Experience Cloud environments, potentially exposing sensitive information such as credit card numbers and health records. Organizations using Salesforce are advised to immediately audit their access control configurations, disable self-registration if not required, and monitor for unauthorized use of the identified methods using the provided Splunk detection searches.
