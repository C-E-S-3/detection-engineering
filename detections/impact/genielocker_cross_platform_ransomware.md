# GenieLocker Cross-Platform Ransomware — Windows, Linux, VMware ESXi

## Description

Detects activity associated with **GenieLocker**, a cross-platform ransomware family attributed to **Feral Wolf** (aka Toy Ghouls). GenieLocker targets Windows, Linux, and VMware ESXi environments, and is the final-stage payload in a campaign that begins with Atlassian Confluence exploitation (CVE-2023-22515) or 1C:Enterprise credential abuse, followed by a prolonged dwell period using MatrixDoor and MQTTDoor backdoors before ransomware detonation.

Detections cover: known malicious IP IOC, mass file modification consistent with encryption, GSocket reverse shell (Feral Wolf access tool), and precursor service name indicators (MatrixDoor/MQTTDoor).

**False positive sources:** Legitimate backup agents or migration tools performing bulk file operations may trigger the mass-file-modification detection; allowlist by known process name. GSocket may be used by administrators for legitimate tunneling in some environments — baseline before alerting.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| **Tactic** | Impact (TA0040) |
| **Technique** | Data Encrypted for Impact (T1486) |

**Secondary Techniques:**
- Initial Access: Exploit Public-Facing Application (T1190) — CVE-2023-22515 Atlassian Confluence
- Persistence: Create or Modify System Process: Windows Service (T1543.003) — MatrixDoor/MQTTDoor services
- Command and Control: Web Service (T1102) — Matrix/MQTT messaging C2
- Command and Control: Non-Standard Port (T1571) — GSocket reverse shell

## Lockheed Martin Kill Chain Phase

**Actions on Objectives**

## Splunk SPL Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest="45.151.45.31"
     OR All_Traffic.dest_host IN ("meet.element.tw","broker.hivemq.com")
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.dest_port
     All_Traffic.app All_Traffic.bytes_out
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    dest="45.151.45.31", 90,
    dest_host="meet.element.tw", 90,
    dest_host="broker.hivemq.com", 75,
    true(), 60)
| where risk_score >= 75
| table firstTime lastTime src dest dest_host dest_port app bytes_out risk_score
```

## Risk Score Logic

| Score | Condition |
|-------|-----------|
| 90 | Direct hit on `45.151.45.31` — known Feral Wolf GenieLocker campaign infrastructure |
| 90 | Connection to `meet.element.tw` — attacker-controlled Matrix C2 server |
| 75 | Connection to `broker.hivemq.com` — public MQTT broker abused by MQTTDoor |

## Additional Detection: Mass File Encryption (Volume-Based)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.action=modified
  by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_id
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| where count > 200
| eval risk_score=case(count > 1000, 95, count > 500, 88, count > 200, 75, true(), 60)
| where risk_score >= 75
| table firstTime lastTime dest user process_name process_id count risk_score
```

**Risk Score**: 75–95 (High–Critical) — More than 200 file modifications per search window per process is consistent with active ransomware encryption. Tune threshold based on environment.

## Additional Detection: MatrixDoor/MQTTDoor Precursor Process (Endpoint)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("cplsupport.exe","wtas.exe","wtass.exe")
     OR Processes.process_name IN ("gsocket","gs-netcat","gs-sftp")
  by Processes.dest Processes.user Processes.process_name Processes.process_path
     Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name IN ("cplsupport.exe","wtas.exe","wtass.exe"), 95,
    process_name IN ("gsocket","gs-netcat","gs-sftp"), 80,
    true(), 60)
| where risk_score >= 80
| table firstTime lastTime dest user process_name process_path parent_process_name risk_score
```

**Risk Score**: 80–95 (High–Critical) — Exact binary name matches for known Feral Wolf implants. GSocket process execution is anomalous on enterprise endpoints.

## Associated Threat Actors

| Actor | Alias | Campaign |
|-------|-------|---------|
| Feral Wolf | Toy Ghouls | May–August 2026 campaign targeting Russian organizations in retail, construction, manufacturing, and IT; GenieLocker ransomware deployed after prolonged dwell using MatrixDoor/MQTTDoor C2; Kaspersky/BI.ZONE disclosure September 2026 |

## References

- [Securelist: New GenieLocker ransomware for Windows, ESXi, and Linux](https://securelist.com/genielocker-ransomware-for-windows-linux-and-esxi/120843/)
- [The Hacker News: Three Threat Groups Target Russian Enterprises](https://thehackernews.com/2026/09/three-threat-groups-target-russian.html)
- [GBHackers: Feral Wolf Hackers Exploit Confluence and 1C to Deploy GenieLocker](https://gbhackers.com/genielocker-ransomware/)
- [Securelist: Toy Ghouls backdoors (prior research)](https://securelist.com/toy-ghouls-new-hivemq-and-element-backdoors/121270/)
- [MITRE ATT&CK T1486 — Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [CVE-2023-22515 — Atlassian Confluence Broken Access Control](https://nvd.nist.gov/vuln/detail/CVE-2023-22515)
- [Threat Intel: 2026-09-19_securelist-feral-wolf-genielocker-ransomware.md]
- [Prior actor tracking: 2026-09-07_securelist-toy-ghouls-hivemq-element-backdoors.md]
