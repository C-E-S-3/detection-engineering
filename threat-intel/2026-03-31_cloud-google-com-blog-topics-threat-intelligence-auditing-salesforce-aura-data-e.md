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

### Tactic: Collection
- **Technique ID**: T1530
  **Technique Name**: Data from Cloud Storage Object
  **Description**: Misconfigured Salesforce Aura endpoints allow unauthorized access to sensitive data such as credit card numbers and identity documents.

### Tactic: Discovery
- **Technique ID**: T1592
  **Technique Name**: Gather Victim Host Information
  **Description**: Using the `getConfigData` and `getItems` Aura methods, attackers can enumerate Salesforce objects and retrieve records.

### Tactic: Exfiltration
- **Technique ID**: T1041
  **Technique Name**: Exfiltration Over C2 Channel
  **Description**: Misconfigured GraphQL Aura controllers allow attackers to retrieve more than 2,000 records, bypassing standard Salesforce limits.

## 3. Malware & Tools

### Tools
- **AuraInspector**: Open-source tool released by Mandiant to identify and audit access control misconfigurations in Salesforce Aura.

## 4. Threat Actor / Campaign Attribution

- **Threat Actor**: Not explicitly attributed to a named group.
- **Campaign**: No specific campaign identified.
- **Motivations**: Likely financial or espionage-related, given the sensitivity of the data exposed (e.g., credit card numbers, identity documents).
- **Targeted Sectors**: Organizations using Salesforce Experience Cloud, particularly those with misconfigured access controls.

## 5. Splunk Detection Searches

### Detecting Misuse of Aura Methods

#### Search for `getConfigData` and `getItems` API calls in Salesforce logs:
```spl
index=your_salesforce_index sourcetype="salesforce:api" 
| search "descriptor"="serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData" OR "descriptor"="serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems"
| stats count by user, ip, descriptor
| where count > 10
```
*Comment*: This search identifies excessive or unusual use of the `getConfigData` and `getItems` methods, which may indicate enumeration attempts.

### Detecting GraphQL Abuse

#### Search for GraphQL Aura controller usage:
```spl
index=your_salesforce_index sourcetype="salesforce:api" 
| search "descriptor"="serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData"
| stats count by user, ip
| where count > 5
```
*Comment*: This search identifies potential abuse of the GraphQL Aura controller to retrieve large datasets.

### Detecting Bulk Actions

#### Search for bulked Aura actions:
```spl
index=your_salesforce_index sourcetype="salesforce:api" 
| search "actions"="*"
| stats count by user, ip
| where count > 100
```
*Comment*: This search identifies bulked actions exceeding recommended limits, which may indicate misuse.

## 6. Executive Summary

Mandiant has released AuraInspector, a tool to identify misconfigurations in Salesforce Aura that could expose sensitive data. Key risks include unauthorized access to Salesforce objects via misconfigured Aura methods (`getConfigData`, `getItems`) and abuse of the GraphQL Aura controller to bypass record retrieval limits. Organizations using Salesforce Experience Cloud should prioritize auditing access controls and monitoring API usage for anomalies. Immediate actions include deploying AuraInspector, reviewing access control configurations, and implementing Splunk detections for suspicious API activity.