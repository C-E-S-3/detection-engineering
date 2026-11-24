# Bling Libra / Com Affiliate Vishing — Python-httpx M365 Automation Indicator

## Description

Detects post-compromise automation activity by Bling Libra (ShinyHunters) Com-affiliated actors — specifically the new Vortex (CL-CRI-1264) and Cinder (CL-CRI-1274) clusters — following a vishing-facilitated Adversary-in-the-Middle (AiTM) credential and session-token capture.

After intercepting a victim's Microsoft 365 credentials and MFA session over a vishing call, attackers replay the captured tokens using Python scripts built on the `httpx` async HTTP library. The `python-httpx` user-agent string in Entra ID sign-in logs and M365 Unified Audit Log resource-access events is a high-fidelity indicator of this actor-side automation — no legitimate enterprise user or service generates this user-agent in Entra ID sign-in paths.

A secondary behavioral signal is high-volume scripted access to SharePoint, OneDrive, or Exchange Online in a short window via Python HTTP client strings, representing the bulk data collection phase before extortion.

Cinder (CL-CRI-1274) specifically replays **persistent session tokens** through proxy infrastructure to bypass subsequent Duo MFA challenges — reducing push-notification noise that might otherwise alert the victim. Detecting this pattern is therefore important even when no abnormal MFA activity is logged.

**False positive sources:**
- Legitimate automation connecting to M365 Graph API may use Python `httpx` or `requests` — validate against known service principals and registered app IDs before escalating.
- IT tooling (PowerShell scripts, Python admin utilities) using legacy auth endpoints — these should be migrated to service principal auth and would not appear under a user identity.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Credential Access |
| Tactic ID | TA0006 |
| Technique | Adversary-in-the-Middle |
| Technique ID | T1557 |
| Secondary Tactic | Collection |
| Secondary Tactic ID | TA0009 |
| Secondary Technique | Automated Collection |
| Secondary Technique ID | T1119 |
| Tertiary Technique | Data from Cloud Storage |
| Tertiary Technique ID | T1530 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

### Query 1 — Entra ID Sign-In with `python-httpx` User-Agent (Primary IoA)

Catches attacker automation replaying captured session tokens — the distinctive `python-httpx` user-agent should never appear in legitimate Entra ID interactive or non-interactive sign-in logs for end-user accounts.

```spl
`o365` Workload="AzureActiveDirectory" Operation="UserLoggedIn"
| rex field=_raw "\"Name\":\"UserAgent\",\"Value\":\"(?P<user_agent>[^\"]+)\""
| where match(user_agent, "(?i)python-httpx")
| stats count min(_time) as firstTime max(_time) as lastTime
        values(user_agent) as user_agents values(ClientIP) as src_ips
        by UserId UserDisplayName ResultStatus
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    ResultStatus="Succeeded", 90,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime UserId UserDisplayName src_ips user_agents ResultStatus count risk_score
```

### Query 2 — Bulk M365 Cloud Data Access via Python HTTP Client

Detects the bulk collection phase: high-volume scripted SharePoint, OneDrive, or Exchange access events from a Python HTTP library user-agent in a short time window.

```spl
`o365` Workload IN ("SharePoint", "OneDrive", "Exchange")
    (Operation="FileAccessed" OR Operation="MailItemsAccessed" OR
     Operation="SearchQueryInitiatedSharePoint" OR Operation="ListItems")
| rex field=_raw "\"Name\":\"UserAgent\",\"Value\":\"(?P<user_agent>[^\"]+)\""
| where match(user_agent, "(?i)python-httpx|python-requests|requests/[0-9]")
| bucket _time span=5m
| stats count as access_count
        min(_time) as firstTime max(_time) as lastTime
        values(user_agent) as user_agents values(ClientIP) as src_ips
        values(Operation) as operations dc(FileName) as unique_files
        by UserId _time
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    access_count >= 100, 95,
    access_count >= 25, 85,
    access_count >= 5, 70)
| where risk_score >= 70
| table firstTime lastTime UserId src_ips user_agents operations access_count unique_files risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| `python-httpx` user-agent + successful Entra ID login | 90 | No legitimate enterprise user generates this user-agent; near-certain indicator of token-replay automation |
| `python-httpx` user-agent + failed Entra ID login | 65 | Attacker attempting token replay that failed; still warrants investigation |
| 100+ M365 object accesses in 5 min via Python UA | 95 | Bulk scripted exfiltration in progress |
| 25–99 M365 object accesses in 5 min via Python UA | 85 | Likely scripted collection; investigate |
| 5–24 M365 object accesses in 5 min via Python UA | 70 | Suspicious volume; correlate with recent auth anomalies |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Bling Libra / ShinyHunters (Vortex CL-CRI-1264) | [Unit 42 — Dialing for Data (2026-11-20)](https://unit42.paloaltonetworks.com/com-affiliate-vishing-attacks/) |
| Bling Libra / ShinyHunters (Cinder CL-CRI-1274) | [Unit 42 — Dialing for Data (2026-11-20)](https://unit42.paloaltonetworks.com/com-affiliate-vishing-attacks/) |
| UNC6671 / BlackFile | [Google TI — BlackFile Vishing Operation (2026-05-15)](https://cloud.google.com/blog/topics/threat-intelligence/blackfile-vishing-extortion-operation) |
| Scattered Spider / UNC3944 | [CISA Advisory AA23-320A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a) |

## References

- [Unit 42 — Dialing for Data: Inside the Com's High-Profile Heists (2026-11-20)](https://unit42.paloaltonetworks.com/com-affiliate-vishing-attacks/)
- [MITRE ATT&CK — T1557: Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)
- [MITRE ATT&CK — T1119: Automated Collection](https://attack.mitre.org/techniques/T1119/)
- [MITRE ATT&CK — T1530: Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
- [MITRE ATT&CK — T1098.005: Account Manipulation: Device Registration](https://attack.mitre.org/techniques/T1098/005/)
- [CISA — Phishing-Resistant MFA Fact Sheet](https://www.cisa.gov/resources-tools/resources/phishing-resistant-mfa-fact-sheet)
