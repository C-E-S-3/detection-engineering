# GigaWiper (BLUERABBIT) Destructive Backdoor — Non-Standard C2 Ports and Scheduled Task Persistence

## Description

Detects GigaWiper (also tracked as BLUERABBIT by Google GTIG and Binary Defense), a Golang-based Windows backdoor that combines multi-modal destructive wiping, fake ransomware (Crucio component), VNC-like remote control, screen capture, and espionage capabilities into a single operator-dispatched framework. GigaWiper uses RabbitMQ AMQP on the non-standard port 5544 and Redis on port 7542 for C2, and persists via a scheduled task named `OneDrive Update` running at one-minute intervals.

Three high-signal detection surfaces are covered:

1. **Non-standard AMQP/Redis C2 ports** (5544, 7542) — RabbitMQ on port 5544 and Redis on port 7542 have no legitimate Windows desktop use cases. A fanout exchange allows operators to issue simultaneous disk-wipe commands to all infected hosts.
2. **Scheduled task named `OneDrive Update` at 1-minute recurrence** — persistence masquerading as a legitimate Microsoft task, created via `schtasks.exe` with `/sc MINUTE` and the exact name `OneDrive Update`.
3. **Direct IP IOC match** — raw index hit against the two confirmed GigaWiper C2 addresses (`185.182.193[.]21`, `212.8.248[.]104`).

False positives for the port detection: RabbitMQ is used legitimately in server/microservice environments — alert suppression for known server infrastructure is advisable. The `OneDrive Update` task name is not used by any legitimate Microsoft product. The direct IP search has negligible false positive risk.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| **Tactic** | Impact (TA0040) |
| **Primary Technique** | T1561.002 — Disk Wipe: Disk Structure Wipe |
| **Secondary Techniques** | T1486 — Data Encrypted for Impact (Crucio fake ransomware); T1529 — System Shutdown/Reboot; T1561.001 — Disk Wipe: Disk Content Wipe (FlockWiper) |
| **Supporting Techniques** | T1053.005 — Scheduled Task/Job: Scheduled Task (persistence); T1571 — Non-Standard Port (C2); T1036.004 — Masquerading: Masquerade Task or Service; T1562.001 — Impair Defenses: Disable or Modify Tools; T1113 — Screen Capture; T1021.001 — Remote Services: RDP |

## Lockheed Martin Kill Chain Phase

**Actions on Objectives** (destruction, data exfiltration, remote control)
**Command & Control (C2)** (RabbitMQ/Redis non-standard ports)
**Installation** (OneDrive Update scheduled task persistence)

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where (All_Traffic.dest_port=5544 OR All_Traffic.dest_port=7542)
  AND All_Traffic.action!="blocked"
by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.transport
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src dest dest_port transport risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="schtasks.exe"
  AND (Processes.process="*OneDrive Update*"
       AND (Processes.process="*/sc MINUTE*" OR Processes.process="*/sc minute*"))
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
index=* (dest="185.182.193.21" OR dest="212.8.248.104")
| stats count min(_time) as firstTime max(_time) as lastTime by src dest dest_port
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| table firstTime lastTime src dest dest_port risk_score
```

## Risk Score Logic

| Score | Condition |
|-------|-----------|
| 100 | Direct connection to known GigaWiper C2 IPs (`185.182.193.21`, `212.8.248.104`) |
| 95 | Outbound connection to non-standard AMQP port 5544 or Redis port 7542 (not blocked) |
| 75 | `schtasks.exe` creating a task named `OneDrive Update` with `/sc MINUTE` recurrence |

The port 5544/7542 detections score 95 because while RabbitMQ/Redis are legitimate services, outbound connections to these ports from Windows workstations or endpoints have essentially no legitimate use case. Server-to-server traffic should be whitelisted per environment.

## Associated Threat Actors

| Actor | Notes |
|-------|-------|
| GigaWiper / BLUERABBIT | Golang destructive Windows backdoor; combines Crucio fake-ransomware (.candy extension, unrecoverable AES wipe), FlockWiper (multi-pass disk content wipe), and physical disk structure wipe (IOCTL_DISK_CREATE_DISK + randomized overwrite); RabbitMQ fanout exchange enables simultaneous mass destruction across all infected hosts; attributed to likely Iran-nexus group by Google GTIG and Binary Defense based on Israeli targeting |

## References

- [Microsoft Security Blog — GigaWiper (2026-07-09)](https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/)
- [The Register — GigaWiper (2026-07-10)](https://www.theregister.com/security/2026/07/10/destructive-windows-backdoor-stuffs-multiple-wipers-and-ransomware-code-into-a-single-package/5270053)
- [The Hacker News — GigaWiper (2026-07-10)](https://thehackernews.com/2026/07/new-gigawiper-windows-backdoor-bundles.html)
- [CISA Advisory AA23-335A — Crucio ransomware (December 2023)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-335a)
- [MITRE ATT&CK T1561.002 — Disk Wipe: Disk Structure Wipe](https://attack.mitre.org/techniques/T1561/002/)
- [MITRE ATT&CK T1486 — Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK T1571 — Non-Standard Port](https://attack.mitre.org/techniques/T1571/)
- [MITRE ATT&CK T1053.005 — Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
