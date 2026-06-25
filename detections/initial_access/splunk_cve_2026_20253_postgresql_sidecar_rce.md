# Splunk Enterprise PostgreSQL Sidecar Unauthenticated RCE (CVE-2026-20253)

## Description

Detects active exploitation of CVE-2026-20253, a CVSS 9.8 missing-authentication vulnerability in Splunk Enterprise's PostgreSQL sidecar service. The sidecar endpoint performs no credential verification, allowing any network-reachable attacker to invoke file operations on the underlying system. A public PoC from watchTowr Labs (June 12, 2026) demonstrates that the PostgreSQL `lo_export` file-write primitive chains directly into shell command execution.

**Strategic severity**: This vulnerability targets the SIEM itself. A compromised Splunk instance not only achieves RCE on a high-privilege server but also grants write access to log pipelines, enabling log tampering that blinds the entire monitoring stack. CISA added CVE-2026-20253 to the Known Exploited Vulnerabilities catalog on June 18, 2026 with a 3-day federal patch deadline.

False positives: Legitimate PostgreSQL maintenance operations run by Splunk DBAs; tune by excluding known management source IPs.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |

Secondary Techniques:
- T1059.004 — Command and Scripting Interpreter: Unix Shell (lo_export chain to shell execution)
- T1083 — File and Directory Discovery (filesystem enumeration via PostgreSQL functions)
- T1505.003 — Server Software Component: Web Shell (post-exploitation persistence)
- T1562.001 — Impair Defenses: Disable or Modify Tools (SIEM compromise blinds detection stack)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.parent_process_name IN ("splunkd","splunk-helper","python","python3")
     AND Processes.process_name IN ("pg_dump","pg_restore","psql","bash","sh",
                                     "curl","wget","nc","ncat","chmod","id","whoami"))
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name IN ("curl","wget","nc","ncat") AND parent_process_name="splunkd", 93,
    process_name IN ("bash","sh") AND parent_process_name="splunkd", 90,
    process_name IN ("pg_dump","pg_restore","psql"), 87,
    process_name IN ("id","whoami","chmod"), 82,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where (Filesystem.file_path LIKE "%/opt/splunk/etc/apps/%"
      OR Filesystem.file_path LIKE "%/opt/splunk/etc/deployment-apps/%"
      OR Filesystem.file_path LIKE "%/opt/splunk/var/run%")
    AND Filesystem.action IN ("created","modified")
    AND (Filesystem.file_name LIKE "%.py" OR Filesystem.file_name LIKE "%.sh"
      OR Filesystem.file_name LIKE "%.php" OR Filesystem.file_name LIKE "*.conf")
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.action
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_name, "\.php$"), 92,
    match(file_name, "\.sh$") AND match(file_path, "apps"), 88,
    match(file_name, "\.py$") AND match(file_path, "apps"), 82,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user file_path file_name action risk_score
```

```spl
| comment "CVE-2026-20253: Detect outbound network connections initiated by Splunk processes (post-exploitation reverse shell or exfil)"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.app IN ("splunkd","splunk")
    AND NOT All_Traffic.dest_ip IN ("0.0.0.0/8","127.0.0.0/8","10.0.0.0/8",
                                     "172.16.0.0/12","192.168.0.0/16")
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(dest_port IN (4444,8888,1337,9001,9002), 93, dest_port > 1024, 80, 1=1, 70)
| where risk_score >= 70
| table firstTime lastTime src dest dest_ip dest_port app risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| splunkd spawning curl/wget/nc (download/reverse shell) | 93 | Near-certain post-exploitation; splunkd should never spawn network utilities |
| splunkd spawning bash/sh | 90 | High confidence OS command injection via lo_export chain |
| PostgreSQL utilities (pg_dump/psql) child of Splunk | 87 | Direct lo_export exploitation of PostgreSQL sidecar |
| .php file created in Splunk app directories | 92 | Web shell staging (PHP not used by Splunk natively) |
| .sh script created in Splunk app dir | 88 | Shell persistence in Splunk app context |
| Splunk process making outbound internet connection | 80–93 | Reverse shell or data exfiltration |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Multiple opportunistic actors (RaaS affiliates, initial access brokers) | Active exploitation confirmed by Splunk (June 18, 2026) |
| watchTowr Labs (PoC only, not malicious) | [watchTowr PoC writeup (2026-06-12)](https://labs.watchtowr.com/cve-2026-20253-splunk-postgresql) |

## References

- [CISA KEV — CVE-2026-20253 (June 18, 2026)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Help Net Security — Splunk Enterprise CVE-2026-20253 under active exploitation (2026-06-19)](https://www.helpnetsecurity.com/2026/06/19/splunk-vulnerability-cve-2026-20253-exploited/)
- [SOCRadar — CVE-2026-20253 CISA Splunk RCE](https://socradar.io/blog/cve-2026-20253-cisa-splunk-enterprise-rce/)
- [MITRE ATT&CK — T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [Splunk Advisory — CVE-2026-20253 (patch to 10.0.7 or 10.2.4)](https://advisory.splunk.com/advisories/SVD-2026-0001)
