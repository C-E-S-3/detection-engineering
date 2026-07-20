# HollowGraph M365 Calendar Dead-Drop C2

## Description

Detects HollowGraph, a .NET DLL espionage implant that uses a hijacked Microsoft 365 calendar as a two-way command-and-control dead drop. The operator plants a calendar event at **2050-05-13** — far enough in the future that the mailbox owner will never scroll to it — and attaches encrypted operator tasking as a file attachment. The implant authenticates to Microsoft Graph API using compromised Entra ID credentials and queries for calendar events at that date using:

```
GET https://graph.microsoft.com/v1.0/me/events?$filter=start/dateTime ge '2050-01-01'
```

It reads the tasking attachment (encrypted with RSA + AES-256-GCM), executes either the `get` (file collection) or `send` (exfiltration upload) command, and writes collected data back to the same event as a new attachment. HollowGraph uses a secondary DNS tunneling channel exclusively to receive refreshed Entra ID credentials after token expiry — this avoids any connection to attacker-owned infrastructure.

Because all traffic uses legitimate Microsoft Graph API endpoints (`graph.microsoft.com`), network controls keyed to attacker-owned destinations have nothing to flag. The technique is detectable only through URL-level proxy inspection (the `2050` date filter in the URI query string), M365 Unified Audit Log analysis (calendar events created at far-future dates, unusual attachment operations), or behavioral indicators on the endpoint (non-Outlook/Teams process establishing Graph API connections).

Group-IB discovered HollowGraph in July 2026, finding it on at least 12 machines with activity running from June 3 to July 9, 2026. Group-IB attributes the campaign with high confidence to **Cavern Manticore**, an Iranian Ministry of Intelligence and Security (MOIS)-linked actor that operates the Cavern modular backdoor framework, based on shared command syntax and internal tasking. Low-confidence overlap with the Iranian-nexus Lyceum group was also noted.

**Expected false positives:**
- Non-browser Graph API calendar access: legitimate line-of-business .NET apps, RPA bots, or custom calendar sync tools may also call `/me/events`. Scope with an allowlist of known-good Microsoft App Registration IDs (`AppId` in M365 UAL) before escalating.
- 2050 date in Graph API URL: essentially zero FP rate — no legitimate calendar application generates events or date filters for a date 24+ years in the future.
- DNS TXT high-entropy queries: higher FP rate from SPF/DKIM records, ACME certificate challenges, and CDN TXT ownership proofs. Correlate with Graph API calendar access on the same host before escalating.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Web Service: Bidirectional Communication |
| Technique ID | T1102.002 |
| Secondary Tactic | Exfiltration |
| Secondary Tactic ID | TA0010 |
| Secondary Technique | Exfiltration Over Alternative Protocol: DNS |
| Secondary Technique ID | T1048.001 |
| Tertiary Technique | Application Layer Protocol: DNS |
| Tertiary Technique ID | T1071.004 |
| Tertiary Technique | Valid Accounts: Cloud Accounts |
| Tertiary Technique ID | T1078.004 |
| Supporting Technique | Encrypted Channel: Symmetric Cryptography (AES-256-GCM) |
| Supporting Technique ID | T1573.001 |
| Supporting Technique | Encrypted Channel: Asymmetric Cryptography (RSA) |
| Supporting Technique ID | T1573.002 |
| Supporting Technique | Automated Collection |
| Supporting Technique ID | T1119 |
| Supporting Technique | Automated Exfiltration |
| Supporting Technique ID | T1020 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control |
| Actions on Objectives |

## Splunk Detection Queries

### Query 1: Non-Browser Process Accessing Graph API Calendar Endpoint (Proxy/Network)

Detects endpoint processes that are not known M365 clients establishing HTTPS connections to `graph.microsoft.com` on `/me/events` or `/users/*/events` calendar paths. HollowGraph runs as a .NET DLL loaded by a host process; that process will appear here instead of Outlook or Teams.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_host="graph.microsoft.com"
  AND All_Traffic.dest_port=443
  AND (All_Traffic.url_path="*/me/events*"
       OR All_Traffic.url_path="*/me/calendar*"
       OR All_Traffic.url_path="*/users/*/events*"
       OR All_Traffic.url_path="*/users/*/calendar*")
  AND NOT All_Traffic.app IN (
    "outlook","olk.exe","teams","ms-teams","onedrive","lync","skype",
    "msedge","chrome","firefox","iexplore","brave","safari","chromium",
    "opera","vivaldi","edge")
by All_Traffic.src All_Traffic.dest_host All_Traffic.url_path
   All_Traffic.app All_Traffic.process_name
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(url_path, "2050"), 98,
    match(process_name, "(?i)powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32"), 90,
    match(process_name, "(?i)cmd\.exe|conhost"), 85,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime src dest_host url_path app process_name risk_score
```

### Query 2: Graph API Calendar Query with 2050 Date IOC (Proxy/Network)

The highest-confidence single-event indicator: a Graph API URL containing "2050" in the query string or path. HollowGraph uses `?$filter=start/dateTime ge '2050-01-01'` or accesses the specific event at `2050-05-13`. No legitimate calendar application generates these queries.

```spl
index=proxy OR index=web OR index=network
dest_host="graph.microsoft.com"
(uri_path="*/events*" OR uri_path="*/calendar*")
| rex field=uri_query "(?i)(?P<year_2050>2050(?:-\d{2}){0,2})"
| where isnotnull(year_2050)
| eval risk_score=98, note="HollowGraph IOC: Graph API calendar query with 2050 date dead-drop filter"
| table _time src dest_host uri_path uri_query process_name risk_score note
```

### Query 3: M365 Unified Audit Log — Calendar Event at 2050 Date (Operator Action)

Detects the adversary-side action of planting or updating the C2 dead-drop calendar event with a start date in 2050. This is an operator action, not the implant — it catches the moment the attacker seeds or refreshes the tasking.

```spl
`o365`
| where (Workload IN ("Exchange","MicrosoftTeams","OfficeSuite"))
  AND match(Operation, "(?i)Create|Update|Set|Add")
  AND (
    match('coalesce(StartTime, "")', "2050")
    OR match('coalesce(ModifiedProperties{}.NewValue, "")', "2050")
    OR match(_raw, "2050-05-13")
    OR match(_raw, "\"2050\"")
  )
| eval risk_score=98
| table _time UserId ClientIPAddress AppId Operation ObjectId risk_score
| sort -risk_score _time
```

### Query 4: M365 Unified Audit Log — Calendar Attachment Operations (Exfil / Tasking Retrieval)

Detects HollowGraph reading tasking from or writing exfiltrated files to calendar event attachments via Graph API. Multiple attachment operations against the same calendar event in a short window strongly indicates automated C2 polling or exfiltration.

```spl
`o365`
| where Workload IN ("Exchange","OfficeSuite")
  AND match(Operation, "(?i)Attach")
| stats count min(_time) as firstTime max(_time) as lastTime
    dc(Operation) as op_count values(Operation) as operations
    values(ClientIPAddress) as src_ips values(AppId) as app_ids
    values(ObjectId) as object_ids
    by UserId
| where count >= 3
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    count >= 20, 92,
    count >= 10, 85,
    count >= 5,  78,
    1=1, 70)
| table firstTime lastTime UserId src_ips app_ids operations op_count count risk_score
| sort -risk_score -count
```

### Query 5: DNS TXT Queries with High-Entropy Subdomains (Entra Credential Tunnel)

Detects the HollowGraph secondary channel that delivers refreshed Entra ID credentials via DNS TXT record tunneling. High-entropy long subdomain labels prepended to an attacker-controlled zone are the signal; correlate with Graph API calendar activity on the same host.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.record_type="TXT"
by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval labels=split(query,".")
| eval label_count=mvcount(labels)
| eval first_label=mvindex(labels,0)
| eval first_label_len=len(first_label)
| eval query_len=len(query)
| where label_count >= 4 AND first_label_len >= 20 AND query_len >= 45
| eval note="High-entropy TXT query: possible HollowGraph Entra credential DNS tunnel"
| eval risk_score=case(
    first_label_len >= 40, 72,
    first_label_len >= 30, 65,
    1=1, 55)
| table firstTime lastTime src query answer label_count first_label_len query_len risk_score note
| sort -first_label_len
```

### Query 6: Correlation — Non-M365 Graph Calendar Access + 2050 Date + DNS TXT (Same Host, 15-Minute Window)

High-confidence correlation rule combining Graph API calendar access, 2050-date indicator, and high-entropy DNS TXT query on the same host within 15 minutes. All three together is essentially a confirmed HollowGraph C2 session.

```spl
(index=proxy OR index=network OR index=web OR index=dns)
| eval event_type=case(
    (dest_host="graph.microsoft.com" AND match(uri_path,"(?i)/(?:me|users)/.*(?:events|calendar)") AND NOT match(process_name,"(?i)outlook|teams|onedrive|msedge|chrome|firefox")), "graph_calendar_nonbrowser",
    (dest_host="graph.microsoft.com" AND match(coalesce(uri_query,uri_path,""), "2050")), "graph_calendar_2050",
    (record_type="TXT" AND len(mvindex(split(dns_query,"."),0)) >= 20), "dns_txt_highentr",
    1=1, null())
| where isnotnull(event_type)
| eval bucket_time=floor(_time/900)*900
| stats values(event_type) as event_types dc(event_type) as type_count
    values(uri_path) as paths values(process_name) as procs
    by host bucket_time
| where type_count >= 2
| eval confirmed=if(mvfind(event_types,"graph_calendar_2050") >= 0, "HollowGraph_2050_IOC", "HollowGraph_Behavioral")
| eval risk_score=case(
    confirmed="HollowGraph_2050_IOC" AND type_count >= 3, 99,
    confirmed="HollowGraph_2050_IOC", 96,
    type_count >= 3, 88,
    1=1, 80)
| table bucket_time host procs paths event_types confirmed risk_score
| sort -risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| 2050 date in Graph API calendar URL + prior non-browser Graph calendar access (correlation) | 99 | Near-certain HollowGraph C2 confirmation; no legitimate scenario matches |
| Graph API calendar URL containing "2050" (single event) | 98 | IOC-level; zero legitimate FP use case for 24-year-future calendar filter |
| M365 UAL: calendar event created/modified with 2050 date | 98 | Operator planting or refreshing dead-drop; investigate immediately |
| Correlation: Graph calendar + DNS TXT + 2050 (3 signals) | 99 | Full composite match; immediate IR warranted |
| 20+ calendar attachment operations in 2-minute window | 92 | Automated exfiltration cycle in progress; scope by AppId |
| Non-browser process → graph.microsoft.com/v1.0/me/events | 75-90 | Depends on process type; PowerShell/LOLBin rates 90, unknown .NET 80 |
| DNS TXT with 40+ char first label | 72 | Correlate with Graph activity; standalone FP rate is higher |
| M365 UAL: 3-5 calendar attachment operations by same user | 70 | Enrichment; investigate AppId and source IP |

## Associated Threat Actors

| Actor | Relationship |
|-------|-------------|
| Cavern Manticore (MOIS-linked, Iran) | High-confidence primary attribution by Group-IB; shared command syntax (`get`/`send`) and internal tasking infrastructure match the Cavern modular backdoor framework |
| Lyceum (Iran-nexus) | Low-confidence overlap noted by Group-IB; unconfirmed as of 2026-07-20 |

## References

- [The Hacker News — HollowGraph Malware Hides C2 and Stolen Files in M365 Events Dated 2050](https://thehackernews.com/2026/07/hollowgraph-malware-hides-c2-and-stolen.html)
- [BleepingComputer — New HollowGraph malware uses Microsoft Graph for stealthy C2 comms](https://www.bleepingcomputer.com/news/security/new-hollowgraph-malware-uses-microsoft-graph-for-stealthy-c2-comms/)
- [The Register — Microsoft 365 calendars become spy drop boxes in HOLLOWGRAPH campaign](https://www.theregister.com/security/2026/07/20/microsoft-365-calendars-become-spy-drop-boxes-in-hollowgraph-campaign/5274982)
- [Infosecurity Magazine — New HollowGraph Malware Hijacks Microsoft 365 Calendars for Covert C2](https://www.infosecurity-magazine.com/news/hollowgraph-microsoft-calendars/)
- [MITRE ATT&CK — T1102.002: Web Service: Bidirectional Communication](https://attack.mitre.org/techniques/T1102/002/)
- [MITRE ATT&CK — T1071.004: Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/)
- [MITRE ATT&CK — T1048.001: Exfiltration Over Alternative Protocol: DNS](https://attack.mitre.org/techniques/T1048/001/)
- [MITRE ATT&CK — T1078.004: Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
- [MITRE ATT&CK — T1573.001: Encrypted Channel: Symmetric Cryptography](https://attack.mitre.org/techniques/T1573/001/)
- [MITRE ATT&CK — T1119: Automated Collection](https://attack.mitre.org/techniques/T1119/)
- [Glassworm comparison — CrowdStrike (2026-05-26) — Google Calendar dead-drop C2](https://www.crowdstrike.com/en-us/blog/inside-crowdstrike-takedown-of-a-developer-targeting-botnet/)
- [APT37 NarwhalRAT pCloud dead-drop comparison — Genians (2026-06)](https://www.genians.co.kr/en/blog/threat_intelligence/narwhalrat)
