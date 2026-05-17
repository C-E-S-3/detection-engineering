# UNC6671 / BlackFile — O365 SharePoint Bulk File Exfiltration via Scripting User Agent

## Description

Detects bulk SharePoint file collection via programmatic scripting clients (`python-requests`, `WindowsPowerShell`, `curl`, `Go-http-client`) from non-managed devices. This is the data exfiltration phase of UNC6671's (BlackFile) attack chain, where the attacker uses stolen session cookies and the Microsoft Graph API to stream hundreds of thousands to millions of files.

A critical evasion behavior: UNC6671 deliberately generates `FileAccessed` events rather than `FileDownloaded` events because many SIEM rules and DLP tools treat `FileAccessed` as benign activity. Both event types are searched here. A secondary indicator is `ClientAppId` spoofed as the Microsoft Office App ID (`d3590ed6-52b3-4102-aeff-aad2292ab01c`) while the actual `UserAgent` reveals a scripting engine.

**False positive sources:** Legitimate Power Automate flows, SharePoint migration tools, or developer scripts accessing SharePoint. These should be operated from managed devices with approved service principals, not from commercial VPN IPs with personal OAuth tokens. Validate against known automation service principal IDs and approved egress IPs.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Collection |
| Tactic ID | TA0009 |
| Technique | Data from Cloud Storage |
| Technique ID | T1530 |
| Secondary Technique | Data from Information Repositories: SharePoint |
| Secondary Technique ID | T1213.002 |
| Tertiary Technique | Exfiltration Over Web Service |
| Tertiary Technique ID | T1567.002 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

### Query 1 — High-Volume SharePoint File Access via Scripting Agent

```spl
`o365` Workload="SharePoint"
    (Operation="FileAccessed" OR Operation="FileDownloaded")
    (UserAgent="python-requests*" OR UserAgent="WindowsPowerShell*"
     OR UserAgent="curl/*" OR UserAgent="Go-http-client/*")
| rename UserId as user, ClientIP as src_ip,
         SourceFileName as file_name, SiteUrl as site_url
| stats count as file_access_count
    min(_time) as firstTime
    max(_time) as lastTime
    values(src_ip) as src_ips
    values(UserAgent) as user_agents
    values(Operation) as operations
    dc(file_name) as unique_files_accessed
    by user site_url
| where file_access_count >= 100
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    file_access_count >= 10000, 95,
    file_access_count >= 1000, 85,
    file_access_count >= 100, 65)
| where risk_score >= 65
| table firstTime lastTime user src_ips user_agents file_access_count unique_files_accessed operations site_url risk_score
```

### Query 2 — Microsoft Office App ID Spoofed with Scripting User Agent (Session Cookie Theft Indicator)

```spl
`o365` Workload="SharePoint"
    (Operation="FileAccessed" OR Operation="FileDownloaded")
    ClientAppId="d3590ed6-52b3-4102-aeff-aad2292ab01c"
    (UserAgent="python-requests*" OR UserAgent="WindowsPowerShell*"
     OR UserAgent="curl/*" OR UserAgent="Go-http-client/*")
| rename UserId as user, ClientIP as src_ip,
         SourceFileName as file_name, SiteUrl as site_url
| stats count as access_count
    min(_time) as firstTime
    max(_time) as lastTime
    values(src_ip) as src_ips
    values(UserAgent) as user_agents
    dc(file_name) as unique_files_accessed
    by user ClientAppId
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime user src_ips user_agents access_count unique_files_accessed ClientAppId risk_score
```

### Query 3 — Hunting: Any Scripting Agent in SharePoint Audit Logs (Lower Threshold)

```spl
`o365` Workload="SharePoint"
    (UserAgent="python-requests*" OR UserAgent="WindowsPowerShell*"
     OR UserAgent="curl/*" OR UserAgent="Go-http-client/*"
     OR UserAgent="python/*" OR UserAgent="Java/*")
| rename UserId as user, ClientIP as src_ip, UserAgent as user_agent
| stats count as access_count
    min(_time) as firstTime
    max(_time) as lastTime
    values(src_ip) as src_ips
    values(Operation) as operations
    dc(SourceFileName) as unique_files
    by user user_agent
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    access_count >= 1000, 80,
    access_count >= 10, 50,
    1=1, 25)
| table firstTime lastTime user src_ips user_agent access_count unique_files operations risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| 100–999 file access events, scripting UA | 65 | Suspicious volume; possible automation or exfiltration; investigate |
| 1,000–9,999 file access events, scripting UA | 85 | High-confidence malicious; no legitimate workflow accesses thousands of files with raw HTTP client |
| 10,000+ file access events, scripting UA | 95 | Near-certain exfiltration; UNC6671 observed accessing 1M+ files in single sessions |
| Spoofed Microsoft Office App ID + scripting UA | 85 | Session cookie theft confirmed; App ID is that of MS Office but agent is Python/PowerShell |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| UNC6671 / BlackFile | [Google TI — BlackFile Vishing Operation (2026-05-15)](https://cloud.google.com/blog/topics/threat-intelligence/blackfile-vishing-extortion-operation) |
| Scattered Spider (UNC3944) | [CISA — Scattered Spider Advisory AA23-320A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a) |
| Octo Tempest (DEV-0537 / Lapsus$) | [Microsoft — MSTIC Octo Tempest Profile](https://www.microsoft.com/en-us/security/blog/2023/10/25/octo-tempest-crosses-boundaries-to-facilitate-extortion-hybrid-identity-attacks/) |

## References

- [Google TI — Welcome to BlackFile: Inside a Vishing Extortion Operation](https://cloud.google.com/blog/topics/threat-intelligence/blackfile-vishing-extortion-operation)
- [MITRE ATT&CK — T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
- [MITRE ATT&CK — T1213.002: Data from Information Repositories: SharePoint](https://attack.mitre.org/techniques/T1213/002/)
- [MITRE ATT&CK — T1567.002: Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/002/)
- [Microsoft — SharePoint Unified Audit Log Schema](https://learn.microsoft.com/en-us/microsoft-365/compliance/audit-log-activities)
