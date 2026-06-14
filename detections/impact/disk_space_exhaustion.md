# Disk Space Exhaustion — Endpoint Denial of Service / Data Destruction

## Description

Detects filesystem exhaustion (ENOSPC — No Space Left On Device) across Linux hosts and Docker containers. Disk exhaustion can be caused by legitimate data growth, but it is also a technique used by adversaries to:

- Deny logging capability (fill disk to stop security logs being written — T1562.006)
- Stage large exfiltration payloads (T1074.001)
- Deploy ransomware that encrypts files and inflates disk usage (T1486)
- Deliberately exhaust resources to cause service outages (T1499)

This detection targets both hard ENOSPC errors (disk 100% full, writes failing) and soft warnings (≥ 90% usage) before impact occurs. Docker container overlay filesystem exhaustion is separately detected as it can indicate container data growth from malware or uncontrolled logging inside a container.

Common false positives: backup jobs writing large datasets, log rotation misconfiguration, legitimate database growth, container image layer accumulation, Prometheus TSDB or Loki log retention without proper retention limits. Tune by adding exclusions for known high-write processes when investigating.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Impact |
| Tactic ID | TA0040 |
| Technique | Endpoint Denial of Service |
| Technique ID | T1499 |
| Sub-technique | Service Exhaustion Flood |
| Sub-technique ID | T1499.002 |

| Field | Value |
|-------|-------|
| Tactic | Impact |
| Tactic ID | TA0040 |
| Technique | Data Destruction |
| Technique ID | T1485 |

| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Tactic ID | TA0005 |
| Technique | Impair Defenses: Indicator Blocking |
| Technique ID | T1562.006 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Wazuh Rules

| Rule ID | Level | Description |
|---------|-------|-------------|
| 101500 | 0 | Base anchor: syslog ENOSPC events |
| 101501 | 12 | Kernel ENOSPC — filesystem 100% full |
| 101502 | 10 | Userspace process ENOSPC |
| 101503 | 8 | Filesystem >= 90% usage warning |
| 101504 | 9 | Wazuh rootcheck disk anomaly |
| 101510 | 11 | Docker container overlay disk full |
| 101511 | 13 | Repeated Docker disk-full errors (sustained pressure) |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process="*No space left on device*"
     OR Processes.process="*ENOSPC*"
  by Processes.dest Processes.user Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user process_name process
```

**Supplemental: Disk usage monitoring via syslog**

```spl
index=syslog (sourcetype=linux_messages OR sourcetype=syslog)
  ("No space left on device" OR "ENOSPC" OR "disk full")
| eval severity=case(
    match(_raw, "(?i)kernel.*ENOSPC"),           "critical",
    match(_raw, "(?i)No space left on device"),  "high",
    1=1,                                          "medium")
| stats count min(_time) as firstTime max(_time) as lastTime
  by host source severity
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime host source severity count
```

**Supplemental: Docker container overlay disk exhaustion**

```spl
index=docker_logs (sourcetype=docker OR sourcetype="docker:container")
  ("No space left on device" OR "ENOSPC" OR "overlay" AND "no space")
| stats count min(_time) as firstTime max(_time) as lastTime
  by host container_name
| where count > 3
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(count > 20, 85, count > 5, 70, 1=1, 55)
| table firstTime lastTime host container_name count risk_score
```

**Supplemental: Pre-emptive high disk usage (> 90%)**

```spl
index=syslog (sourcetype=linux_messages OR sourcetype=syslog)
  | rex "(?P<mount>/[^\s]+)\s+(?P<pct>\d+)%"
  | where pct >= 90
  | eval risk_score=case(pct >= 99, 90, pct >= 95, 75, pct >= 90, 50)
  | stats max(pct) as max_pct max(risk_score) as risk_score
      min(_time) as firstTime max(_time) as lastTime
    by host mount
  | where risk_score >= 50
  | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)`
  | table firstTime lastTime host mount max_pct risk_score
```

## Risk Score Logic

| Score | Condition |
|-------|-----------|
| 90-95 | Kernel ENOSPC — writes actively failing |
| 80-89 | Repeated Docker container disk-full errors |
| 70-79 | Single userspace ENOSPC or Docker disk-full |
| 50-69 | Filesystem >= 95% usage |
| 40-49 | Filesystem >= 90% usage |

## Triage Guidance

1. **Identify the affected filesystem** — check `df -h` output to confirm which mount is full
2. **Find the top consumers** — `du -sh /* 2>/dev/null | sort -rh | head -20` 
3. **Check for rapid growth** — compare timestamps of large files against recent process/container activity
4. **Correlate with other alerts** — look for concurrent data exfiltration (T1041), ransomware (T1486), or log deletion (T1070.002) alerts on the same host
5. **Container-specific** — if Docker overlay is full, inspect container via `docker system df` and `docker logs <container>` for the offending process

## Associated Threat Actors

| Actor | Technique | Notes |
|-------|-----------|-------|
| Scattered Spider / UNC3944 | T1485, T1499 | Uses disk wipe utilities to destroy evidence |
| LockBit | T1486 | Ransomware encryption fills disks |
| Akira / REDBIKE | T1486, T1485 | Multi-stage encryption + evidence destruction |
| FIN7 | T1074.001 | Data staging in temp dirs exhausts disk before exfil |

## References

- [MITRE ATT&CK T1499 — Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)
- [MITRE ATT&CK T1485 — Data Destruction](https://attack.mitre.org/techniques/T1485/)
- [MITRE ATT&CK T1562.006 — Impair Defenses: Indicator Blocking](https://attack.mitre.org/techniques/T1562/006/)
- [Wazuh rootcheck disk space monitoring](https://documentation.wazuh.com/current/user-manual/capabilities/policy-monitoring/rootcheck/index.html)
- [Linux kernel ENOSPC error handling](https://www.kernel.org/doc/html/latest/filesystems/vfs.html)
