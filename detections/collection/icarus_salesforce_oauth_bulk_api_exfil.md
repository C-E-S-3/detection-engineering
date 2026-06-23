# Icarus / Supply Chain OAuth Token Abuse — Salesforce Bulk CRM Exfiltration

## Description

Detects anomalous bulk exfiltration of Salesforce CRM data through OAuth tokens obtained via
third-party integration compromise. In the June 2026 Klue supply chain breach, the Icarus extortion
group (possibly linked to ShinyHunters/UNC6240) obtained a dormant, never-revoked OAuth credential
from a decommissioned Klue integration prototype and used it to issue refresh tokens for connected
customer Salesforce instances. Automated Python scripts then bulk-queried Salesforce standard objects
(Opportunity, Case, Contact, Lead, Account, User, Contract, Event, Campaign) via the REST API,
exfiltrating CRM records from hundreds of organizations over 6-hour windows.

This detection targets the behavioral pattern — anomalous OAuth token usage by a third-party
connected app with a scripting user-agent and abnormal API query volume — rather than specific
threat-actor infrastructure that may change between campaigns.

False positives: Legitimate ETL pipelines and data-warehouse integrations using Python to pull
Salesforce data on schedule. Tune by baselining expected connected-app query volumes and creating
per-app allowlists for known-good automation. Risk score thresholds should be adjusted to your
Salesforce environment's normal API call volume.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Collection |
| Tactic ID | TA0009 |
| Technique | Data from Information Repositories |
| Technique ID | T1213 |
| Secondary Tactic | Initial Access |
| Secondary Technique | Valid Accounts: Cloud Accounts |
| Secondary Technique ID | T1078.004 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

These queries require Salesforce EventLog File data ingested via the Salesforce Add-on for Splunk
or equivalent connector. Adjust the `` `salesforce` `` macro to match your environment's index/sourcetype.

```spl
`salesforce` EventType=RestApi
  (user_agent="Python-urllib*" OR user_agent="*python*"
    OR user_agent="curl*" OR user_agent="Go-http-client*")
  uri="/services/data/*/query*"
| bucket span=15m _time
| stats count as queries_in_window
    sum(number_soql_queries) as soql_total
    values(entity_name) as objects_queried
    values(user_agent) as user_agents
    values(uri) as uris
    by _time src_ip user connected_app
| eval risk_score=case(
    queries_in_window > 500 AND match(user_agents, "Python-urllib/3\\.1[2-9]"), 95,
    queries_in_window > 200, 85,
    queries_in_window > 50 AND match(user_agents, "(?i)python|curl|wget|go-http"), 75,
    1=1, 50)
| where risk_score >= 75
| `security_content_ctime(_time)`
| table _time src_ip user connected_app user_agents queries_in_window soql_total objects_queried risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| >500 API queries in 15 min + Python-urllib/3.12 or /3.14 user-agent | 95 | Matches Icarus exfiltration burst pattern exactly; near-certain malicious activity |
| >200 API queries in any 15-minute window | 85 | Unusual API burst from any source; investigate connected app and source IP |
| >50 API queries in 15 min with scripting user-agent (Python, curl, Go) | 75 | Likely automated; legitimate ETL tools should be allowlisted and will not trigger if tuned |
| Any scripting user-agent in Salesforce RestApi logs | 50 | Context enrichment; useful for correlation when combined with other indicators |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Icarus extortion group (active April 2026+; possibly linked to ShinyHunters/UNC6240) | [Datadog Security Labs — Detecting the Klue supply chain attack (2026-06-22)](https://securitylabs.datadoghq.com/articles/detecting-the-klue-supply-chain-attack-in-salesforce/), [Huntress — Klue Breach Investigation (2026-06-22)](https://www.huntress.com/blog/klue-breach-investigation) |
| ShinyHunters / UNC6240 | [MITRE ATT&CK — UNC6240](https://attack.mitre.org/groups/G1017/), [Mandiant — ShinyHunters](https://cloud.google.com/blog/topics/threat-intelligence/shinyhunters-targets-education-sector-oracle-exploit) |

## References

- [Datadog Security Labs — Detecting the Klue supply chain attack in Salesforce (2026-06-22)](https://securitylabs.datadoghq.com/articles/detecting-the-klue-supply-chain-attack-in-salesforce/)
- [Huntress — Cybercrime Breaches Klue: Salesforce Data Impacted (2026-06-22)](https://www.huntress.com/blog/klue-breach-investigation)
- [BleepingComputer — Klue OAuth breach linked to 'Icarus' Salesforce data theft attacks (2026-06-22)](https://www.bleepingcomputer.com/news/security/klue-oauth-breach-linked-to-icarus-salesforce-data-theft-attacks/)
- [TechCrunch — Klue hack results in data breach at several cybersecurity firms (2026-06-22)](https://techcrunch.com/2026/06/22/klue-hack-results-in-data-breach-at-several-cybersecurity-firms/)
- [ReliaQuest — Klue Integration Abused in Salesforce Data Theft](https://reliaquest.com/blog/threat-spotlight-integration-abused-in-crm-data-theft/)
- [MITRE ATT&CK — T1213: Data from Information Repositories](https://attack.mitre.org/techniques/T1213/)
- [MITRE ATT&CK — T1078.004: Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
