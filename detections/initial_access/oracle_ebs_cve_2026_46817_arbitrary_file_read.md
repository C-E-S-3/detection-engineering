# Oracle EBS ibytransmit Unauthenticated Arbitrary File Read (CVE-2026-46817)

## Description

Detects active exploitation of CVE-2026-46817, an unauthenticated arbitrary file read vulnerability in Oracle E-Business Suite (EBS) 12.1.x and 12.2.x affecting the `/OA_HTML/ibytransmit` servlet. An unauthenticated attacker sends an HTTP POST with an XML payload using the `CODEX_PULL` scheme and `FULL_FILE_PATH` parameter to read any server-side file accessible to the Oracle application user, including OS credential files (`/etc/passwd`, `/etc/shadow`), Oracle wallet certificates, database connection strings (`tnsnames.ora`), and EBS admin credentials. Added to CISA KEV June 27, 2026; patched in Oracle CPU April 2026.

**Expected false positives:** Legitimate Oracle EBS administrative traffic may access `/OA_HTML/` paths, but POST requests specifically to `/OA_HTML/ibytransmit` are not expected from normal EBS users. The User-Agent `ibytransmit-lab-poc/1.0` is an unambiguous exploitation indicator.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access (TA0001) |
| Technique | T1190 — Exploit Public-Facing Application |
| Sub-technique | N/A |
| Secondary tactic | Credential Access (TA0006) |
| Secondary technique | T1552.001 — Unsecured Credentials: Credentials In Files |

## Lockheed Martin Kill Chain Phase

| Phase | Applies |
|-------|---------|
| Delivery | Yes — unauthenticated HTTP request delivers exploit payload |
| Actions on Objectives | Yes — file read directly achieves attacker goal of credential theft |

## Splunk Detection Query

### Query 1 — Oracle EBS ibytransmit Endpoint Exploitation (Web Data Model)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Web.Web
where (Web.url="*/OA_HTML/ibytransmit*"
       OR Web.http_user_agent="ibytransmit-lab-poc/1.0"
       OR Web.url LIKE "%CODEX_PULL%"
       OR Web.url LIKE "%FULL_FILE_PATH=%")
by Web.src Web.dest Web.url Web.http_user_agent Web.http_method Web.status
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(http_user_agent, "(?i)ibytransmit-lab-poc"), 95,
    match(url, "(?i)/OA_HTML/ibytransmit") AND http_method="POST", 90,
    match(url, "(?i)CODEX_PULL|FULL_FILE_PATH"), 88,
    match(url, "(?i)/OA_HTML/ibytransmit"), 80,
    1=1, 60)
| where risk_score >= 80
| table firstTime lastTime src dest url http_user_agent http_method status risk_score
```

### Query 2 — Known CVE-2026-46817 Exploitation Source IP

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.src_ip IN ("45.84.137.125")
   OR All_Traffic.dest_ip IN ("45.84.137.125")
by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.action
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src_ip dest_ip dest_port action risk_score
```

## Risk Score Logic

| Score | Condition |
|-------|-----------|
| 95 | User-Agent matches `ibytransmit-lab-poc` — unambiguous PoC exploitation |
| 95 | Traffic to/from known exploitation source IP 45.84.137.125 |
| 90 | POST to `/OA_HTML/ibytransmit` — active exploitation attempt |
| 88 | URL contains CODEX_PULL or FULL_FILE_PATH parameter — exploit payload pattern |
| 80 | Any request to `/OA_HTML/ibytransmit` — reconnaissance/probing |

## Associated Threat Actors

| Actor | Notes | References |
|-------|-------|-----------|
| Unknown (CVE-2026-46817 exploiters, June 2026) | Automated PoC scanning observed from 45.84.137.125 with User-Agent `ibytransmit-lab-poc/1.0`; opportunistic credential harvesting targeting unpatched Oracle EBS instances; no specific APT attribution | [CISA KEV — June 27 2026](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [The Hacker News](https://thehackernews.com/2026/06/oracle-ebs-cve-2026-46817-active-exploitation.html) |

## References

- [The Hacker News — Oracle EBS CVE-2026-46817](https://thehackernews.com/2026/06/oracle-ebs-cve-2026-46817-active-exploitation.html)
- [CISA KEV — June 27 2026 Addition](https://www.cisa.gov/news-events/alerts/2026/06/27/cisa-adds-one-known-exploited-vulnerability-catalog)
- [Oracle Critical Patch Update April 2026](https://www.oracle.com/security-alerts/cpuapr2026.html)
- [MITRE ATT&CK — T1190](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1552.001](https://attack.mitre.org/techniques/T1552/001/)
