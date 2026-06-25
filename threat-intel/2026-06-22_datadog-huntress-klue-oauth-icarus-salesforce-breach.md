---
scraped_at: 2026-06-23T00:00:00Z
source_url: https://securitylabs.datadoghq.com/articles/detecting-the-klue-supply-chain-attack-in-salesforce/
report_type: threat-intel
severity: high
title: "Icarus Extortion Group Exploits Klue OAuth Integration to Exfiltrate Salesforce CRM Data from Hundreds of Organizations"
---

## 1. IOCs

### IP Addresses

| Indicator | Type | Context |
|-----------|------|---------|
| 138.226.246[.]94 | IPv4 | Icarus attacker IP observed in Salesforce RestApi audit logs during exfiltration (June 11–12, 2026); Netherlands or France-region ISP |
| 212.86.125[.]24 | IPv4 | Icarus attacker IP observed during Klue OAuth exfiltration campaign; Netherlands or France-region ISP |
| 213.111.148[.]90 | IPv4 | Icarus attacker IP; Netherlands, France, or Ukraine-region ISP |
| 94.154.32[.]160 | IPv4 | Icarus attacker IP; Netherlands, France, or Ukraine-region ISP |

### User-Agent Strings

| Indicator | Context |
|-----------|---------|
| Python-urllib/3.12 | HTTP user-agent observed in Salesforce RestApi event logs during automated bulk CRM data exfiltration |
| Python-urllib/3.14 | HTTP user-agent observed during sustained exfiltration windows (up to 6 hours); Salesforce QueryMore calls to bypass 2,000-record API limit |

### Communication Infrastructure

| Indicator | Context |
|-----------|---------|
| Session Messenger (ID: "mr bean" / Icarus group) | Extortion communication channel; victims directed to contact attacker via Session Messenger encrypted messaging |
| Compromised Australian retail domains | Source domains for initial extortion emails; threat actor leveraged hacked legitimate domains to avoid email blocklists |

### Salesforce API Indicators

| Indicator | Context |
|-----------|---------|
| `/services/data/v59.0/query/*` | Salesforce REST API query endpoint abused for bulk CRM record extraction |
| `SELECT FIELDS(STANDARD) FROM Event` | Broad field-selection query pattern observed in attacker-controlled API sessions |
| ~1,000 API queries in 15 minutes; 6+ hour sustained windows | Anomalous query volume pattern in Klue Battlecards connected app sessions |

---

## 2. TTPs (MITRE ATT\&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1078.004 | Valid Accounts: Cloud Accounts | Attacker obtained dormant OAuth credential from a Klue integration prototype that was never decommissioned; credential granted access to customer OAuth token issuance |
| Collection | T1213 | Data from Information Repositories | Automated mass exfiltration of Salesforce objects: Opportunity, Case, Task, Lead, Contact, Account, User, Contract, Event, Campaign |
| Collection | T1530 | Data from Cloud Storage Object | Salesforce CRM data accessed via REST API using stolen OAuth refresh tokens |
| Exfiltration | T1567 | Exfiltration Over Web Service | Exfiltration channel is Salesforce's own REST API; data pulled via attacker-controlled Python scripts |
| Execution | T1059.006 | Command and Scripting Interpreter: Python | Python scripts automate Salesforce REST API queries; Python-urllib user-agent observed in audit logs |
| Impact | T1657 | Financial Theft / Extortion | Icarus extortion group demands ransom; threatens publication of stolen CRM data on leak site |
| Resource Development | T1078 | Valid Accounts | Attacker leveraged never-revoked legacy OAuth credential from decommissioned integration prototype to compromise Klue backend |

---

## 3. Malware & Tools

| Name | Type | Notes |
|------|------|-------|
| Python urllib (stdlib) | Living-off-the-land | Attacker used Python standard library (no custom malware) to automate Salesforce REST API queries; user-agent Python-urllib/3.12 and /3.14 |
| Session Messenger | Extortion tool | Encrypted messaging app used for attacker-victim extortion communication; operator ID "mr bean" / Icarus |
| Icarus leak site | Extortion infrastructure | Data leak site operated since April 28, 2026; lists victims to pressure ransom payment |

---

## 4. Threat Actor / Campaign Attribution

| Attribute | Detail |
|-----------|--------|
| Actor | Icarus (extortion group, active since April 28, 2026) |
| Nexus | Cybercrime (financially motivated extortion) |
| Possible affiliation | ShinyHunters (UNC6240); ShinyHunters Telegram channel claimed Klue breach on June 21, 2026, posting evidence attributed to "Icarus" operator |
| TTM | June 11 breach → June 12 Klue discovers → June 13 Klue disables credentials → June 21 Icarus claims → June 22 victim list grows |
| Confirmed victims | Huntress, Recorded Future, Tanium, Jamf, Sprout Social, Gong, Insurity; estimated hundreds of organizations total |
| Data stolen | Business contacts, sales pipeline data, pricing, opportunity notes, CRM records from Salesforce instances |

**Prior ShinyHunters activity tracked in this repo:**
- UNC6240 (ShinyHunters) Oracle PeopleSoft CVE-2026-35273 campaign (June 2026, `2026-06-11_cloud-google-com-blog-topics-threat-intelligence-shinyhunters-oracle-peoplesoft-cve-2026-35273.md`)

---

## 5. Splunk Detection Searches

These queries assume Salesforce EventLog File data is ingested via the Salesforce Add-on for Splunk or equivalent connector. Use the `` `salesforce` `` source macro per repo SPL conventions.

### 5a. Anomalous Python Automation in Salesforce Connected App Sessions

```spl
`salesforce` EventType=RestApi
  (user_agent="Python-urllib*" OR user_agent="*python*urllib*")
| stats count min(_time) as firstTime max(_time) as lastTime
    sum(number_soql_queries) as total_queries
    values(entity_name) as queried_objects
    by src_ip user user_agent connected_app
| eval risk_score=case(
    total_queries > 500, 90,
    total_queries > 100, 80,
    match(user_agent, "Python-urllib/3\\.1[2-9]"), 75,
    1=1, 50)
| where risk_score >= 75
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src_ip user user_agent connected_app total_queries queried_objects risk_score
```

### 5b. Salesforce OAuth Token Login from Scripting User-Agent

```spl
`salesforce` EventType=Login
  (login_sub_type="OAuthRefreshToken" OR login_sub_type="OAuth Refresh Token")
  (user_agent="Python*" OR user_agent="curl*" OR user_agent="Go-http-client*")
| stats count min(_time) as firstTime max(_time) as lastTime
    values(src_ip) as src_ips values(user_agent) as user_agents
    by user connected_app
| eval risk_score=case(
    match(user_agent, "Python-urllib/3\\.1[2-9]"), 90,
    match(user_agent, "(?i)python|curl|wget"), 75,
    1=1, 60)
| where risk_score >= 75
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime user connected_app src_ips user_agents count risk_score
```

### 5c. Salesforce Bulk CRM Object Query via Third-Party App (Threat Hunt)

```spl
`salesforce` EventType=RestApi
  uri="/services/data/*/query*"
  (entity_name="Opportunity" OR entity_name="Contact" OR entity_name="Account"
   OR entity_name="Lead" OR entity_name="User" OR entity_name="Contract")
| bucket span=15m _time
| stats count as queries_per_window
    values(entity_name) as objects_queried
    by _time src_ip connected_app user
| where queries_per_window > 200
| eval risk_score=case(
    queries_per_window > 800, 90,
    queries_per_window > 400, 80,
    1=1, 70)
| `security_content_ctime(_time)`
| table _time src_ip connected_app user queries_per_window objects_queried risk_score
```

---

## 6. Executive Summary

Beginning June 11, 2026, the Icarus extortion group — potentially linked to ShinyHunters (UNC6240) — exploited a dormant, never-decommissioned OAuth credential in Klue's integration backend to generate OAuth refresh tokens for connected customer Salesforce instances. Using automated Python scripts (Python-urllib/3.12 and /3.14), the attackers issued up to 1,000 API queries in 15-minute windows to bulk-extract records from Salesforce standard objects including Opportunity, Case, Task, Lead, Contact, Account, User, Contract, Event, and Campaign. The attacker issued QueryMore requests to bypass the 2,000-record API limit, sustaining extraction windows of 6+ hours.

Klue detected anomalous activity June 12 and disabled the integration credentials June 13. By June 21, Icarus publicly claimed responsibility via the ShinyHunters Telegram channel and began extorting victims. Confirmed victims include Huntress, Recorded Future, Tanium, Jamf, Sprout Social, Gong, and Insurity; hundreds of additional organizations are believed affected.

The attack vector — a forgotten integration credential from a proof-of-concept prototype — highlights a critical blind spot in OAuth governance: third-party SaaS integrations often retain long-lived OAuth permissions long after the use case is retired.

**Recommended actions:**
- Block IPs 138.226.246[.]94, 212.86.125[.]24, 213.111.148[.]90, and 94.154.32[.]160 at the perimeter
- Audit all Salesforce Connected Apps and revoke OAuth tokens for apps not in active production use
- Alert on Python-urllib user-agents in Salesforce RestApi event logs
- Alert on >200 Salesforce API queries in any 15-minute window from a single source IP
- Implement IP allowlisting for third-party Salesforce integrations where operationally feasible
- Enable Salesforce Shield Event Monitoring for Transaction Security Policies on anomalous query volume
