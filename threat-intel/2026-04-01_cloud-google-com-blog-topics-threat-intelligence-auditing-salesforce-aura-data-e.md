---
scraped_at: "2026-01-12T00:00:00Z"
source_url: "https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure/"
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)
No specific IOCs (IP addresses, domains, hashes, etc.) were identified in the source content.

## 2. TTPs (MITRE ATT&CK Mapping)
- **Tactic:** Initial Access
  - **Technique ID:** T1190 (Exploit Public-Facing Application)
  - **Description:** Exploitation of misconfigured Salesforce Aura endpoints to gain unauthorized access to sensitive data, including credit card numbers, identity documents, and health information.

- **Tactic:** Collection
  - **Technique ID:** T1530 (Data from Cloud Storage Object)
  - **Description:** Use of Salesforce Aura methods to retrieve sensitive data from misconfigured access controls, including the ability to bypass Salesforce’s 2,000-record retrieval limit using GraphQL queries and sorting parameters.

- **Tactic:** Discovery
  - **Technique ID:** T1087.002 (Account Discovery: Domain Accounts)
  - **Description:** Abuse of Salesforce Aura methods to enumerate accessible records and objects, including the use of `getConfigData` and `getItems` methods.

- **Tactic:** Credential Access
  - **Technique ID:** T1556.004 (Application Access Token)
  - **Description:** Abuse of self-registration endpoints to create unauthorized accounts for accessing Salesforce instances.

## 3. Malware & Tools
- **Tool:** AuraInspector
  - **Description:** Open-source tool released by Mandiant to identify and audit access control misconfigurations in Salesforce Aura framework.

## 4. Threat Actor / Campaign Attribution
No specific threat actor or campaign attribution was provided in the source content.

## 5. Splunk Detection Searches
### Detect Misuse of Salesforce Aura Methods
```spl
index=proxy sourcetype=bluecoat:proxysg
| search cs_uri_path="*/serviceComponent/*" OR cs_uri_path="*/apex/*"
| stats count by cs_uri_path, cs_username, http_method
| where count > 100
| table cs_uri_path, cs_username, http_method, count
# This search identifies unusual activity involving Salesforce Aura methods, such as excessive requests to serviceComponent or apex endpoints.
```

### Detect GraphQL Queries Exceeding Normal Limits
```spl
index=proxy sourcetype=bluecoat:proxysg
| search cs_uri_path="*/graphql/*" AND http_method="POST"
| rex field=_raw "\"query\":\"(?<graphql_query>[^"]+)\""
| stats count by graphql_query, cs_username
| where count > 50
| table graphql_query, cs_username, count
# This search identifies potentially malicious GraphQL queries based on high request volume.
```

### Detect Self-Registration Endpoint Access
```spl
index=proxy sourcetype=bluecoat:proxysg
| search cs_uri_path="*/self-registration/*"
| stats count by cs_uri_path, cs_username, http_method
| where count > 10
| table cs_uri_path, cs_username, http_method, count
# This search identifies potential abuse of self-registration endpoints.
```

### Detect Unusual Record Retrieval via Aura Methods
```spl
index=proxy sourcetype=bluecoat:proxysg
| search cs_uri_path="*/ACTION$getItems" OR cs_uri_path="*/ACTION$getConfigData"
| stats count by cs_uri_path, cs_username, http_method
| where count > 50
| table cs_uri_path, cs_username, http_method, count
# This search identifies excessive use of record retrieval methods in Salesforce Aura.
```

## 6. Executive Summary
Mandiant has released a new open-source tool, AuraInspector, to help organizations identify and mitigate access control misconfigurations in the Salesforce Aura framework. These misconfigurations can allow unauthorized access to sensitive data, including credit card numbers and identity documents. The report highlights several techniques, including the exploitation of Salesforce Aura methods and GraphQL queries, which can bypass standard record retrieval limits and expose sensitive data. Organizations using Salesforce should immediately review their access control configurations, disable self-registration if not required, and monitor for unusual activity involving Salesforce endpoints. Proactive use of the AuraInspector tool is recommended to identify and remediate potential vulnerabilities.
