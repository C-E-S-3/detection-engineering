---
  scraped_at: "2026-01-12T00:00:00Z"
  source_url: "https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure/"
  report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### Domains/URLs
- None identified

### IP Addresses
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
  - **Description**: Misconfigured Salesforce Aura endpoints allow unauthorized access to sensitive data, such as credit card numbers, identity documents, and health information.

### Tactic: Discovery (TA0007)
- **Technique ID**: T1592 - Gather Victim Host Information
  - **Description**: Attackers can use the `getConfigData` Aura method to retrieve a list of objects used in the backend Salesforce database.

- **Technique ID**: T1592.002 - Network Share Discovery
  - **Description**: Misconfigured access controls allow attackers to retrieve records for Salesforce objects using the `getItems` Aura method.

### Tactic: Collection (TA0009)
- **Technique ID**: T1530 - Data from Cloud Storage Object
  - **Description**: Attackers can use the `sortBy` parameter in the `getItems` Aura method to bypass Salesforce's 2,000-record retrieval limit.

### Tactic: Initial Access (TA0001)
- **Technique ID**: T1078 - Valid Accounts
  - **Description**: Attackers can exploit misconfigured self-registration settings to create authenticated accounts and gain access to sensitive data.

### Tactic: Discovery (TA0007)
- **Technique ID**: T1590 - Gather Victim Network Information
  - **Description**: Attackers can use the `getAppBootstrapData` Aura method to retrieve administrative or configuration panel URLs for third-party Salesforce modules.

### Tactic: Collection (TA0009)
- **Technique ID**: T1530 - Data from Cloud Storage Object
  - **Description**: Attackers can use the GraphQL Aura controller to retrieve all records tied to an object, bypassing the 2,000-record limit.

## 3. Malware & Tools
- **Tool**: AuraInspector
  - **Description**: Open-source command-line tool released by Mandiant to identify and audit access control misconfigurations in Salesforce Aura.

## 4. Threat Actor / Campaign Attribution
- **Threat Actor**: None explicitly named
- **Campaign**: None explicitly named
- **Motivations**: Likely data theft, unauthorized access to sensitive information, and potential abuse of misconfigured Salesforce environments.
- **Targeted Sectors/Geographies**: Organizations using Salesforce Experience Cloud, potentially across various industries.

## 5. Splunk Detection Searches

### Detecting Misconfigured Aura Endpoints
```spl
index=proxy_logs
| search uri_path="*/serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData"
| stats count by src_ip, uri_path, http_user_agent
| rename src_ip as "Source IP", uri_path as "Requested URI", http_user_agent as "User Agent"
```

### Detecting Excessive Record Retrieval via Aura
```spl
index=proxy_logs
| search uri_path="*/serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems"
| stats count by src_ip, uri_path, http_user_agent
| where count > 2000
| rename src_ip as "Source IP", uri_path as "Requested URI", http_user_agent as "User Agent"
```

### Detecting GraphQL API Misuse
```spl
index=proxy_logs
| search uri_path="*/graphql"
| stats count by src_ip, uri_path, http_user_agent
| rename src_ip as "Source IP", uri_path as "Requested URI", http_user_agent as "User Agent"
```

### Detecting Access to Self-Registration URLs
```spl
index=proxy_logs
| search uri_path="*/applauncher.LoginFormController/ACTION$getSelfRegistrationUrl"
| stats count by src_ip, uri_path, http_user_agent
| rename src_ip as "Source IP", uri_path as "Requested URI", http_user_agent as "User Agent"
```

### Detecting Access to Administrative URLs
```spl
index=proxy_logs
| search uri_path="*/ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData"
| stats count by src_ip, uri_path, http_user_agent
| rename src_ip as "Source IP", uri_path as "Requested URI", http_user_agent as "User Agent"
```

## 6. Executive Summary
Mandiant has released AuraInspector, an open-source tool to identify and audit access control misconfigurations in Salesforce Aura. These misconfigurations can expose sensitive data, such as credit card numbers and identity documents, to unauthorized users. Attackers can exploit the Aura framework's methods to bypass Salesforce's 2,000-record retrieval limit and access administrative URLs. Organizations using Salesforce Experience Cloud should immediately audit their configurations, disable self-registration if not required, and monitor for suspicious activity targeting Aura endpoints and GraphQL APIs.