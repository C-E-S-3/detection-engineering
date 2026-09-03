# Sangoma Switchvox Unauthenticated SQL Injection to RCE (CVE-2026-9586)

## Description

Detects exploitation of CVE-2026-9586, an unauthenticated SQL injection in the Sangoma Switchvox VoIP phone system's `/pa` (Phone Admin) endpoint. The phone IP parameter is concatenated directly into PostgreSQL queries without sanitization, enabling blind SQL injection. Exploitation escalates to full OS command execution via PostgreSQL's `COPY FROM PROGRAM` extension, which executes arbitrary shell commands as the PostgreSQL service user. Active exploitation observed since August 30, 2026; CISA KEV added September 2, 2026.

Affected version: Switchvox SMB Edition 8.3 (build 104997) and earlier. Patched in Switchvox 8.4.0.2 (released July 14, 2026, pre-dated exploitation). Approximately 4,000 internet-exposed instances, primarily United States SMB deployments.

Attackers have been observed deploying reverse shells following successful exploitation.

**False positive sources:**
- Penetration testing activity against Switchvox systems; coordinate with security teams
- Vulnerability scanners probing the `/pa` endpoint with unexpected IP formats; exclude known scanner ranges

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |
| Secondary Tactic | Execution |
| Secondary Technique | Command and Scripting Interpreter: Unix Shell (T1059.004) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

### Query 1: Suspicious POST to Switchvox /pa Endpoint with SQL Metacharacters

Detects POST requests to the Sangoma Switchvox `/pa` endpoint containing SQL injection metacharacters in parameters — the primary exploitation vector for CVE-2026-9586.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
    values(Web.src) as source_ips values(Web.uri_query) as query_list values(Web.http_user_agent) as user_agents
    from datamodel=Web.Web
    where Web.uri_path="/pa" OR Web.uri_path="/pa/"
    AND Web.http_method=POST
    by Web.dest Web.uri_path
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| search query_list="*'*" OR query_list="*\"*" OR query_list="*--*" OR query_list="*;*"
    OR query_list="*COPY*" OR query_list="*SELECT*" OR query_list="*UNION*" OR query_list="*FROM*"
| eval risk_score=case(
    match(query_list,"COPY.*FROM.*PROGRAM|COPY.*PROGRAM"), 95,
    match(query_list,"UNION.*SELECT|SELECT.*FROM"), 85,
    match(query_list,"'|--|;"), 75)
| where risk_score >= 75
| table firstTime lastTime dest source_ips query_list user_agents count risk_score
```

### Query 2: Web Log — /pa Endpoint Probing with Unexpected IP Format Values

Detects requests to the Switchvox `/pa` endpoint where the phone IP parameter contains non-IP-address values — a lower-fidelity signal useful for identifying scanning or injection attempts before SQL keywords are observed.

```spl
index=* (sourcetype=access_combined OR sourcetype=nginx:access OR sourcetype=apache:access)
(uri="/pa" OR uri="/pa/" OR uri_path="/pa" OR uri_path="/pa/")
| rex field=_raw "(?:phone_ip|phoneip|ip)=(?<phone_ip_param>[^&\s]+)"
| where isnotnull(phone_ip_param)
| eval is_valid_ip=if(match(phone_ip_param,"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"), "true", "false")
| where is_valid_ip="false"
| stats count min(_time) as firstTime max(_time) as lastTime values(src_ip) as source_ips values(phone_ip_param) as injected_values by host uri
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(mvjoin(injected_values," "),"COPY|SELECT|UNION|PROGRAM"), 95,
    count >= 10, 80,
    count >= 3, 70,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime host source_ips uri injected_values count risk_score
```

### Query 3: Unexpected Process Execution from PostgreSQL Service User (Post-Exploitation RCE)

Detects processes spawned by the PostgreSQL service account — the mechanism by which CVE-2026-9586 achieves OS command execution via `COPY FROM PROGRAM`. Requires Sysmon or auditd process telemetry from the Switchvox host.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
    values(Processes.process) as process_list values(Processes.process_path) as paths
    from datamodel=Endpoint.Processes
    where Processes.user IN ("postgres","switchvox","asterisk")
    AND NOT Processes.process_name IN ("postgres","psql","pg_dump","pg_restore","asterisk","safe_asterisk","sh","bash")
    AND NOT Processes.parent_process_name IN ("asterisk","safe_asterisk","systemd","init","supervisord")
    by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_list,"nc|ncat|netcat|curl|wget|python|perl|ruby|bash|sh"), 95,
    match(process_list,"chmod|chown|useradd|passwd|crontab"), 90,
    1=1, 80)
| where risk_score >= 80
| table firstTime lastTime dest user parent_process_name process_name process_list paths count risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| `COPY FROM PROGRAM` in `/pa` request | 95 | Direct RCE exploitation attempt; no benign explanation |
| SQL `UNION SELECT` or `SELECT FROM` in `/pa` request | 85 | Active SQL injection exploitation attempt |
| SQL metacharacters (`'`, `--`, `;`) in `/pa` phone IP param | 75 | Injection attempt; may indicate scanning or early exploitation phase |
| Non-IP-format values in `/pa` phone IP param, 10+ requests | 80 | Automated exploitation or heavy scanning |
| Unexpected process spawned by postgres/switchvox user | 80–95 | Post-exploitation activity; reverse shell or persistence installation |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown opportunistic actors | Active exploitation since August 30, 2026 per BleepingComputer; targeting ~4,000 internet-exposed SMB deployments |
| Potential ransomware affiliates | VoIP system compromise is a known ransomware precursor for SMB targets; Switchvox widely used in healthcare, retail, small business |

## References

- [Sangoma Security Advisory — CVE-2026-9586](https://www.sangoma.com/security-advisory-2026-0002/)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [NVD CVE-2026-9586](https://nvd.nist.gov/vuln/detail/CVE-2026-9586)
- [BleepingComputer — Sangoma Switchvox SQLi RCE Under Active Exploitation](https://www.bleepingcomputer.com/news/security/sangoma-switchvox-sqli-rce-under-active-exploitation/)
- [MITRE ATT&CK T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK T1059.004 — Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
