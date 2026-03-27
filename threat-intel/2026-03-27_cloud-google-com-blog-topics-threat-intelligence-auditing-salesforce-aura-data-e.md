```markdown
---
scraped_at: 2026-01-12T00:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure/
report_type: threat-intel
---

# Threat Intelligence Report: Salesforce Aura Data Exposure

## 1. Indicators of Compromise (IOCs)

### Domains and URLs
- `/s/recordlist/<object>/Default` (Record List endpoint)
- `/applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled` (Self-registration status endpoint)
- `/applauncher.LoginFormController/ACTION$getSelfRegistrationUrl` (Self-registration URL endpoint)
- `/ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData` (Home URLs retrieval endpoint)

### File Names and Paths
- `serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData`
- `serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems`
- `serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews`

### C2 Infrastructure Details
- GraphQL Aura Controller (used for record retrieval)

## 2. TTPs (MITRE ATT&CK Mapping)

### Tactic: Initial Access
- **T1190 - Exploit Public-Facing Application**  
  Misconfigured Salesforce Aura endpoints allow unauthorized access to sensitive data.

### Tactic: Collection
- **T1056.001 - Input Capture: Keylogging**  
  Aura methods like `getConfigData` and `getItems` retrieve sensitive records, including credit card numbers and identity documents.

### Tactic: Persistence
- **T1136.001 - Create Account: Local Account**  
  Exploiting self-registration misconfigurations to create unauthorized accounts.

### Tactic: Discovery
- **T1087.001 - Account Discovery: Local Accounts**  
  Using Aura methods to enumerate accessible records and permissions.

### Tactic: Exfiltration
- **T1020 - Automated Exfiltration**  
  Bulk retrieval of records using Aura's "boxcar'ing" mechanism.

## 3. Malware & Tools

### Malware Families/Names
- **AuraInspector**: Open-source tool by Mandiant for auditing Salesforce Aura misconfigurations.

### Legitimate Tools Abused
- **Salesforce Aura Framework**: Abused for unauthorized data retrieval and access control bypass.

### Custom Tooling Descriptions
- **GraphQL Aura Controller**: Enables retrieval of records beyond the 2,000-record limit, leveraging misconfigurations.

## 4. Threat Actor / Campaign Attribution

### Named Threat Groups
- No specific threat actor attribution provided.

### Campaign Names
- No specific campaign names mentioned.

### Known Affiliations or Motivations
- Likely motivations include data theft (credit card numbers, identity documents, health information) and unauthorized access to Salesforce instances.

### Targeted Sectors and Geographies
- Organizations using Salesforce Experience Cloud across various sectors, including finance, healthcare, and enterprise.

## 5. Splunk Detection Searches

### Detecting Misconfigured Aura Endpoints
```spl
index=web sourcetype=access_combined
| search uri_path IN ("/s/recordlist/*/Default", "/applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled", "/applauncher.LoginFormController/ACTION$getSelfRegistrationUrl", "/ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData")
| stats count by uri_path, client_ip
| where count > 0
```
*Detects access to known misconfigured Aura endpoints.*

### Detecting Bulk Record Retrieval via Aura Boxcar'ing
```spl
index=web sourcetype=access_combined
| search uri_path="/ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems"
| rex field=_raw "actions\":\[(?<actions>[^\]]+)\]"
| eval action_count=mvcount(actions)
| where action_count > 100
| stats count by client_ip, uri_path
```
*Detects bulk record retrieval attempts exceeding recommended limits.*

### Detecting GraphQL Usage for Record Retrieval
```spl
index=web sourcetype=access_combined
| search uri_path="/graphql"
| stats count by client_ip, uri_path
| where count > 0
```
*Detects unauthorized GraphQL queries for record retrieval.*

### Detecting Self-Registration Exploitation
```spl
index=web sourcetype=access_combined
| search uri_path="/applauncher.LoginFormController/ACTION$getSelfRegistrationUrl"
| stats count by client_ip, uri_path
| where count > 0
```
*Detects attempts to exploit self-registration misconfigurations.*

## 6. Executive Summary

Mandiant has identified critical misconfigurations within Salesforce Aura endpoints that allow unauthorized access to sensitive data, including credit card numbers and identity documents. The release of the AuraInspector tool highlights the importance of auditing these configurations to prevent exploitation. Immediate actions include securing misconfigured endpoints, disabling self-registration where unnecessary, and monitoring for bulk data retrieval attempts. Organizations using Salesforce Experience Cloud should prioritize these measures to mitigate risks effectively.
```
