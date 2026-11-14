# Check Point Gaia OS DynamicCLI Local Root Privilege Escalation (CVE-2026-123039)

## Description

Detects exploitation of CVE-2026-123039, a missing-authorization vulnerability in the Check Point Gaia OS `DynamicCLI` daemon. The daemon runs as root and listens on the world-writable Unix socket `/tmp/dynamic_socket` without authenticating connecting processes. Attackers chain this with PHP2Shell web exploitation to escalate from a low-privileged web worker shell to root on the gateway appliance. Post-exploitation stages include TSGA backdoor deployment and deliberate ESXi VMDK/VMX file wiper activity. CISA KEV added November 13, 2026; approximately 24 customers confirmed compromised between October 30 and November 4, 2026.

False positives: Legitimate DynamicCLI daemon activity on Check Point gateways; scheduled gateway maintenance scripts.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Privilege Escalation |
| Tactic ID | TA0004 |
| Technique | Exploitation for Privilege Escalation |
| Technique ID | T1068 |

Secondary tactics: Initial Access (T1190 — PHP2Shell stage), Persistence (T1505.003 — TSGA backdoor), Impact (T1485 — ESXi file destruction).

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

**Rule 1 — Web Server Spawning Shell (PHP2Shell Stage, Initial Access)**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name IN ("httpd", "lighttpd", "nginx", "php", "php-fpm", "php-cgi")
  AND Processes.process_name IN ("sh", "bash", "dash", "ksh", "python", "python3", "perl", "ruby", "nc", "ncat", "curl", "wget")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name, "^(nc|ncat|socat)$"), 95,
    match(process_name, "^(sh|bash|dash)$"), 85,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

**Rule 2 — Root Shell Spawned from Non-Login Process (Post-DynamicCLI Exploitation)**

```spl
`linux_audit`
| search type=EXECVE AND uid=0
| rex field=_raw "argc=(?<argc>\d+)"
| rex field=_raw "a0=\"(?<a0>[^\"]+)\""
| rex field=_raw "a1=\"(?<a1>[^\"]+)\""
| rex field=_raw "ppid=(?<ppid>\d+)"
| where match(a0, "(sh|bash|dash|python|perl)") AND ppid!=1
| stats count min(_time) as firstTime max(_time) as lastTime by host a0 a1 ppid uid
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime host a0 a1 ppid uid risk_score
```

**Rule 3 — ESXi VMDK/VMX Mass Deletion (Impact Stage)**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.action=deleted AND (Filesystem.file_name="*.vmdk" OR Filesystem.file_name="*.vmx" OR Filesystem.file_name="*.nvram")
by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| stats count dc(file_name) as unique_files values(file_name) as deleted_files by dest user process_name firstTime lastTime
| where unique_files >= 3
| eval risk_score=100
| table firstTime lastTime dest user process_name deleted_files unique_files risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Web server spawning reverse shell tools (nc/ncat) | 95 | Strongly indicates PHP2Shell RCE exploitation |
| Web server spawning bash/sh | 85 | Likely PHP2Shell; common in legitimate CGI but should be investigated |
| Web server spawning other interpreters | 70 | Anomalous; most web workers run as nobody/www-data not root |
| Root shell from non-init parent process | 90 | Likely DynamicCLI socket abuse or similar LPE on appliance |
| ≥3 VMware virtual machine files deleted | 100 | Matches observed ESXi wiper post-exploitation behavior; treat as Critical incident |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown (nation-state suspected, unattributed) | [CISA KEV — CVE-2026-123039 (Nov 13, 2026)](https://www.cisa.gov/news-events/alerts/2026/11/13/cisa-adds-two-known-exploited-vulnerabilities-catalog) |
| PHP2Shell campaign operators | [The Hacker News — PHP2Shell and Gaia OS Flaws in Check Point Gateways](https://thehackernews.com/2026/11/hackers-exploit-php2shell-flaws-in.html) |

## References

- [CISA KEV Alert — November 13, 2026](https://www.cisa.gov/news-events/alerts/2026/11/13/cisa-adds-two-known-exploited-vulnerabilities-catalog)
- [CSOOnline — The firewall becomes the foothold](https://www.csoonline.com/article/4248693/the-firewall-becomes-the-foothold-attackers-turn-check-point-gateways-against-customers.html)
- [The Hacker News — Hackers Exploit PHP2Shell Flaws in Check Point Gateways](https://thehackernews.com/2026/11/hackers-exploit-php2shell-flaws-in.html)
- [Safeguard.sh — CVE-2026-123039 DynamicCLI Root](https://safeguard.sh/resources/blog/check-point-gaia-cve-2026-123039-dynamiccli-root-kev)
- [Check Point Advisory sk1000362](https://support.checkpoint.com/results/sk/sk1000362)
- [MITRE ATT&CK — T1068 Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
