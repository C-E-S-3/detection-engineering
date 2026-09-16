# Cisco Secure Email Gateway SQL Injection RCE (CVE-2026-76461)

## Description

Detects exploitation of CVE-2026-76461, a critical SQL injection vulnerability (CVSS 9.8) in Cisco AsyncOS Software for Cisco Secure Email Gateway (SEG). An unauthenticated attacker sends a specially crafted email containing malicious SQL statements to any address handled by the gateway. The AsyncOS email parsing engine processes these without sanitization, and the injected `COPY FROM PROGRAM` PostgreSQL directive executes arbitrary OS commands as root on the appliance.

This detection targets two layers:

1. **Log-based**: Searches Cisco AsyncOS `mail_logs` for `COPY ... TO PROGRAM` SQL patterns — the specific exploitation syntax confirmed by Cisco PSIRT as the primary IOC.
2. **Behavioral**: Detects shell processes spawned by PostgreSQL or AsyncOS mail-handler parent processes, indicating successful command injection and post-exploitation activity.

CVE-2026-76461 was added to the CISA Known Exploited Vulnerabilities catalog on September 14, 2026 — the same day as vendor disclosure — confirming zero-day exploitation prior to patching. A compromised email gateway provides full visibility into all organizational mail in transit.

False positive sources: Legitimate `COPY` SQL statements in database maintenance logs could overlap with this pattern in non-SEG Cisco log sources. Behavioral detection false positives: none expected in production environments; PostgreSQL and AsyncOS processes should not spawn interactive shells.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |
| Secondary Tactic | Execution (TA0002) |
| Secondary Technique | Command and Scripting Interpreter: Unix Shell (T1059.004) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
`cisco_email_gateway` ("COPY" "TO PROGRAM")
| rex field=_raw "(?i)(?P<sql_fragment>COPY\s+\S+\s+(?:FROM|TO)\s+PROGRAM\s+['\"]?[^'\";\r\n]{1,200})"
| rex field=_raw "(?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
| rex field=_raw "(?:from|rcpt|mail from:)\s*<?(?P<mail_from>[^>@\s]+@[^>\s]+)>?"
| stats count min(_time) as firstTime max(_time) as lastTime
    values(sql_fragment) as sql_fragment values(src_ip) as src_ip values(mail_from) as mail_from
    by host
| eval risk_score=95
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime host src_ip mail_from sql_fragment count risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name IN ("postgres","postmaster","asyncos","asyncmail","java")
    AND Processes.process_name IN ("sh","bash","zsh","dash","python","python3","perl","ruby",
                                    "curl","wget","nc","ncat","netcat","nmap","id","whoami")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name,"(?i)(sh|bash|zsh|dash)") AND match(process,"(-c|-i)"), 95,
    match(process_name,"(?i)(curl|wget|nc|ncat|netcat)"), 95,
    match(process_name,"(?i)(id|whoami|uname)"), 90,
    1=1, 85)
| where risk_score >= 85
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| `COPY ... TO PROGRAM` SQL pattern found in mail_logs | 95 | Cisco-confirmed exploitation pattern for CVE-2026-76461; near-certain attack attempt |
| PostgreSQL/AsyncOS parent spawning interactive shell with -c or -i flag | 95 | Successful command injection achieving shell execution; post-exploitation confirmed |
| PostgreSQL/AsyncOS parent spawning download utility (curl, wget, nc) | 95 | Download cradle post-exploitation; attacker downloading backdoor/implant |
| PostgreSQL/AsyncOS parent spawning reconnaissance commands (id, whoami, uname) | 90 | Attacker confirming root access post-exploitation |
| PostgreSQL/AsyncOS parent spawning any unexpected child process | 85 | Anomalous behavior warrants investigation regardless of specific child |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown (zero-day exploitation, pre-September 14, 2026) | [CISA KEV — CVE-2026-76461 (2026-09-14)](https://www.cisa.gov/news-events/alerts/2026/09/14/cisa-adds-one-known-exploited-vulnerability-catalog) |
| Nation-state intelligence collectors (high-value target due to email in-transit access) | [Cisco PSIRT Advisory](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asyncos-sqli-rce-76461) |

## References

- [CISA KEV — CVE-2026-76461 Added 2026-09-14](https://www.cisa.gov/news-events/alerts/2026/09/14/cisa-adds-one-known-exploited-vulnerability-catalog)
- [SecurityOnline — CVE-2026-76461 Cisco Email Gateway RCE](https://securityonline.info/cve-2026-76461-cisco-email-gateway-rce/)
- [The Hacker News — Cisco Secure Email Gateway Flaw Exploited](https://thehackernews.com/2026/09/cisco-secure-email-gateway-flaw.html)
- [Help Net Security — CVE-2026-76461 actively exploited (2026-09-15)](https://www.helpnetsecurity.com/2026/09/15/cve-2026-76461-cisco-email-gateway-zero-day-exploited/)
- [Rapid7 ETR — CVE-2026-76461 Exploitation Analysis](https://www.rapid7.com/blog/post/etr-cve-2026-76461-critical-cisco-secure-email-gateway-vulnerability-exploited-in-the-wild/)
- [MITRE ATT&CK — T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [CWE-89 — Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [PostgreSQL COPY FROM PROGRAM Security Considerations](https://www.postgresql.org/docs/current/sql-copy.html)
