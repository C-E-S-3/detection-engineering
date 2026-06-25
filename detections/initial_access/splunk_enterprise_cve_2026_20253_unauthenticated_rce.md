# Splunk Enterprise Unauthenticated RCE via PostgreSQL Sidecar (CVE-2026-20253)

## Description

Detects exploitation of **CVE-2026-20253**, a CVSS 9.8 missing-authentication vulnerability in Splunk Enterprise 10.0.0–10.0.6 and 10.2.0–10.2.3. The vulnerability exists because the internal PostgreSQL sidecar service endpoint lacks authentication controls, allowing any unauthenticated attacker reachable over the network to invoke file-write operations via PostgreSQL connection string smuggling and the `lo_export` function. Successful exploitation allows arbitrary file creation on the Splunk server and, through subsequent web shell placement or cron injection, full remote code execution as the `splunk` OS user.

CISA added CVE-2026-20253 to the KEV catalog on June 18, 2026. This is the first Splunk vulnerability ever added to the KEV list. Active exploitation was confirmed on June 18, 2026 by the Splunk PSIRT.

This detection alerts on the **post-exploitation phase**: `postgres`/`postmaster` processes spawning unexpected child processes (shells, scripting runtimes, download utilities), which indicates the lo_export → file-write → code-execution chain has succeeded. A secondary approach monitors for PostgreSQL writing files outside of expected database directories.

**False positives:** Legitimate Splunk database maintenance scripts may occasionally invoke `pg_ctl`, `pg_dump`, or similar. These are excluded from the query. Unexpected shells or download utilities launched by `postgres` should be treated as true positives unless specifically whitelisted after investigation. Monitor Splunk Enterprise versions 10.0.x and 10.2.x; this detection is less relevant for Cloud (unaffected) or fully patched 10.0.7+/10.2.4+/10.4.0+ installations.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |
| Secondary Tactic | Persistence |
| Secondary Technique | Server Software Component: Web Shell (T1505.003) |
| Secondary Tactic | Defense Evasion |
| Secondary Technique | Impair Defenses: Disable or Modify Tools (T1562.001) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name IN ("postgres", "postmaster", "psql")
  AND NOT Processes.process_name IN ("postgres", "postmaster", "psql", "pg_ctl", "pg_dump",
                                      "pg_restore", "pg_basebackup", "initdb")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name IN ("cmd.exe", "powershell.exe", "pwsh.exe", "sh", "bash", "zsh",
                     "python", "python3", "perl", "ruby", "php"), 95,
    process_name IN ("curl", "wget", "certutil.exe", "bitsadmin.exe", "nc", "ncat",
                     "whoami", "id", "net", "net1", "nltest", "ipconfig", "ifconfig"), 90,
    1=1, 80)
| where risk_score >= 80
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

**Alternative: Filesystem-based detection** (use when EDR covers the Splunk server host)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.process_name IN ("postgres", "postmaster", "psql")
  AND Filesystem.action="created"
  AND NOT Filesystem.file_path IN ("*/pgsql/data/*", "*/pgsql/log/*", "*/postgresql/*",
                                    "*/splunk/var/lib/splunk/kvstore/*",
                                    "*/splunk/var/lib/splunk/fishbucket/*")
by Filesystem.dest Filesystem.user Filesystem.process_name
   Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_name, "(?i)\\.(php|py|jsp|aspx|sh|rb|pl|cgi)$"), 95,
    match(file_path, "(?i)(/tmp/|/var/run/|/etc/cron|/opt/splunk/appserver/)"), 85,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user process_name file_path file_name risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| postgres spawns a shell interpreter (sh, bash, powershell, python, etc.) | 95 | Near-certain exploitation; postgres has no legitimate reason to spawn interactive shells |
| postgres spawns a recon or download utility (curl, wget, whoami, id, etc.) | 90 | High-confidence exploitation; attacker enumerating environment or staging second-stage payload |
| postgres spawns any other non-database child process | 80 | Suspicious; warrants investigation even if legitimate tooling |
| Filesystem: postgres creates file with web/script extension (.php, .py, .sh, .jsp) | 95 | Web shell placement — near-certain true positive on a Splunk host |
| Filesystem: postgres creates file in /tmp/, cron, or Splunk appserver directory | 85 | Likely exploitation artifact or persistence mechanism |
| Filesystem: postgres creates file outside normal db directories | 70 | Requires investigation; could indicate exploit attempt |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown opportunistic actors | Active exploitation confirmed June 18, 2026 per Splunk PSIRT; no specific group attributed |
| Nation-state actors (various) | High-value target: compromising the SIEM blinds defenders prior to broader espionage or destructive action |
| Ransomware affiliates | Pattern of disabling or blinding SIEM/EDR before ransomware deployment; Splunk compromise fits pre-encryption playbook |

## References

- [CISA KEV — CVE-2026-20253 (June 18, 2026)](https://www.cisa.gov/news-events/alerts/2026/06/18/cisa-adds-one-known-exploited-vulnerability-catalog)
- [Help Net Security — Unauthenticated RCE in Splunk Enterprise Under Active Attack](https://www.helpnetsecurity.com/2026/06/19/splunk-vulnerability-cve-2026-20253-exploited/)
- [The Hacker News — Critical Splunk Enterprise Flaw Lets Attackers Run Code Without Authentication](https://thehackernews.com/2026/06/critical-splunk-enterprise-flaw-lets.html)
- [MITRE ATT&CK — T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1505.003 Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [NVD — CVE-2026-20253](https://nvd.nist.gov/vuln/detail/CVE-2026-20253)
