# Arista VeloCloud Orchestrator SQL Injection Privilege Escalation (CVE-2026-114625)

## Description

Detects exploitation of CVE-2026-114625, a CVSS 9.9 SQL injection vulnerability in the Arista VeloCloud Orchestrator (VCO) web management interface. Any authenticated user — including read-only accounts — can submit malicious SQL payloads to escalate their session to Operator or Superuser level. Two attacker IPs have been confirmed exploiting this vulnerability in the wild. Detection combines web traffic anomaly detection (SQLi patterns in VCO requests) with source IP matching against known attacker infrastructure.

False positives are low given the specificity of the SQLi payload patterns. Legitimate VCO API traffic from read-only users will not contain SQL metacharacters in affected parameter fields.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |
| Secondary Tactic | Privilege Escalation |
| Secondary Tactic ID | TA0004 |
| Secondary Technique | Exploitation for Privilege Escalation |
| Secondary Technique ID | T1068 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Web.Web
    where (Web.url="*/velocloud/*" OR Web.url="*/portal/*" OR Web.url="*/login/*")
        AND (Web.src_ip="74.82.197.86" OR Web.src_ip="38.54.50.151"
             OR Web.http_user_agent="*sqlmap*"
             OR Web.uri_query="*UNION*SELECT*" OR Web.uri_query="*' OR '1'='1*"
             OR Web.uri_query="*--*" OR Web.uri_query="*;*DROP*"
             OR Web.uri_query="*SLEEP(*" OR Web.uri_query="*BENCHMARK(*"
             OR Web.uri_query="*WAITFOR DELAY*")
    by Web.src_ip Web.dest Web.url Web.http_method Web.status Web.uri_query Web.http_user_agent
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    src_ip="74.82.197.86" OR src_ip="38.54.50.151", 95,
    http_user_agent="*sqlmap*", 90,
    like(uri_query, "%UNION%SELECT%"), 85,
    like(uri_query, "%SLEEP(%") OR like(uri_query, "%WAITFOR DELAY%"), 80,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime src_ip dest url http_method status uri_query http_user_agent risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Source IP matches known attacker IOC (74.82.197.86 or 38.54.50.151) | 95 | Confirmed active exploitation infrastructure; near-certain true positive |
| User agent contains "sqlmap" | 90 | Automated SQLi tool; minimal false positive rate |
| URI contains UNION SELECT | 85 | Classic SQL injection pattern; rare in legitimate VCO traffic |
| Time-based blind SQLi keywords (SLEEP, WAITFOR DELAY) | 80 | Blind injection attempts |
| Other SQLi metacharacter patterns | 65 | Anomalous; possible scanning or misconfiguration |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown (opportunistic exploitation) | [Arista Advisory 0199](https://www.arista.com/en/support/advisories-notices/security-advisory/20639-security-advisory-0199) |

## References

- [Arista Security Advisory 0199 — CVE-2026-114625](https://www.arista.com/en/support/advisories-notices/security-advisory/20639-security-advisory-0199)
- [The Hacker News — Arista Warns of Critical VeloCloud SQL Injection](https://thehackernews.com/2026/10/arista-warns-of-critical-velocloud-sql.html)
- [MITRE T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE T1068 — Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
