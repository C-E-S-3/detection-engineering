---
title: "Feral Wolf (Toy Ghouls) Deploys GenieLocker Multi-Platform Ransomware Against Russian Organizations"
source: Kaspersky / Securelist; BI.ZONE
source_url: https://securelist.com/genielocker-ransomware-for-windows-linux-and-esxi/120843/
date: 2026-09-19
scraped_at: 2026-09-19T00:00:00Z
report_type: threat-intel
severity: high
tags: [feral-wolf, toy-ghouls, genielocker, ransomware, esxi, linux, windows, confluence, cve-2023-22515, matrixdoor, mqttdoor, gsocket, russia]
mitre_tactics: [TA0001, TA0003, TA0011, TA0040]
---

# Feral Wolf (Toy Ghouls) Deploys GenieLocker Multi-Platform Ransomware Against Russian Organizations

## Executive Summary

Kaspersky and BI.ZONE published research in September 2026 documenting the final stage of a campaign by **Feral Wolf** (also known as **Toy Ghouls**): the deployment of **GenieLocker**, a new cross-platform ransomware targeting Windows, Linux, and VMware ESXi systems. Feral Wolf operated from May through August 2026, exploiting **CVE-2023-22515** in Atlassian Confluence and misconfigured **1C:Enterprise** (1C) systems for initial access, then establishing persistence via the **MatrixDoor** and **MQTTDoor** backdoors before deploying GenieLocker in the ransomware phase. A GSocket-based reverse shell provided an additional C2 access path. The campaign targeted Russian organizations in retail, construction, manufacturing, and IT.

**Note:** The MatrixDoor and MQTTDoor backdoors were previously tracked in `2026-09-07_securelist-toy-ghouls-hivemq-element-backdoors.md`. This report documents the newly disclosed GenieLocker ransomware stage, the CVE-2023-22515 and 1C:Enterprise initial access vectors, and new network infrastructure (`45[.]151[.]45[.]31`).

## IOCs

### IP Addresses

| Indicator | Role |
|-----------|------|
| `45[.]151[.]45[.]31` | Feral Wolf campaign infrastructure (ProtonVPN exit node); associated with GenieLocker ransomware deployment operations |

### Domains

| Indicator | Role |
|-----------|------|
| `meet[.]element[.]tw` | Attacker-controlled Matrix/Element homeserver used by MatrixDoor (`wtass.exe`) for C2 (tracked since Sep 7 report) |
| `broker[.]hivemq[.]com` | Legitimate public MQTT broker abused by MQTTDoor (`cplsupport.exe`) for C2 (tracked since Sep 7 report) |

### File Hashes

Specific GenieLocker payload hashes are not available in public reporting. Refer to Securelist/BI.ZONE full disclosure. Prior MatrixDoor/MQTTDoor hashes: see `2026-09-07_securelist-toy-ghouls-hivemq-element-backdoors.md`.

### Kaspersky Detection Names

| Detection Name | Platform |
|----------------|----------|
| `Trojan-Ransom.Win64.Agent.genie` | Windows |
| `HEUR:TrojanRansom.Win64.Generic` | Windows (heuristic) |
| `Trojan-Ransom.Linux.Agent.genie` | Linux / VMware ESXi |

### Malicious Process / Service Names to Hunt

| Indicator | Description |
|-----------|-------------|
| `cplsupport` / `cplsupport.exe` | MQTTDoor service name; MQTT backdoor masquerading as CPL support process |
| `wtas` / `wtas.exe` / `wtass.exe` | MatrixDoor service name; Matrix backdoor masquerading as Windows TASS service |

## TTPs (MITRE ATT&CK)

| Tactic | Technique | ID | Description |
|--------|-----------|----|-------------|
| Initial Access | Exploit Public-Facing Application | T1190 | CVE-2023-22515 Atlassian Confluence broken access control (CVSS 9.8); creates unauthorized Confluence admin accounts; n-day exploitation |
| Initial Access | Valid Accounts | T1078 | Compromised or default credentials used to access misconfigured 1C:Enterprise (1C) ERP systems |
| Persistence | Create or Modify System Process: Windows Service | T1543.003 | MatrixDoor (`wtas.exe`) and MQTTDoor (`cplsupport.exe`) installed and run as Windows services for persistent access |
| Defense Evasion | Masquerading: Match Legitimate Name or Location | T1036.005 | `cplsupport.exe` mimics a CPL support service; `wtas.exe` mimics a legitimate Windows service; both use MachineGuid-derived keys for config encryption to resist analysis |
| Defense Evasion | Obfuscated Files or Information | T1027 | MQTTDoor config encrypted with ChaCha20-Poly1305; MatrixDoor config stored in `SealedConfig` Windows registry key |
| Command and Control | Web Service | T1102 | Attacker-controlled Matrix/Element homeserver (`meet.element.tw`) used as C2 relay by MatrixDoor |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | MQTT over TCP/8883 (TLS) to HiveMQ public broker abused by MQTTDoor for C2; blends with legitimate MQTT traffic |
| Command and Control | Non-Standard Port | T1571 | GSocket reverse shell used as additional C2 channel; outbound on non-standard ports |
| Lateral Movement | Remote Services: Windows Remote Management | T1021.006 | WinRM (Evil-WinRM) used post-credential for lateral movement and implant staging |
| Impact | Data Encrypted for Impact | T1486 | GenieLocker encrypts Windows, Linux, and VMware ESXi file systems in the campaign's final phase after prolonged dwell |

### Kill Chain Phase
**Delivery → Exploitation → Installation → Command & Control → Actions on Objectives**

## Malware & Tools

| Name | Type | Description |
|------|------|-------------|
| GenieLocker | Cross-platform ransomware | Encrypts Windows (Win64), Linux, and VMware ESXi file systems; Kaspersky: `Trojan-Ransom.Win64.Agent.genie` / `Trojan-Ransom.Linux.Agent.genie`; final payload after prolonged dwell period |
| MatrixDoor (matrix-bird-agent 0.1.0) | Windows backdoor | `wtas.exe` / `wtass.exe`; C2 via attacker-controlled `meet.element.tw` Matrix server; `SealedConfig` registry key for AES-encrypted config; runs as Windows service |
| MQTTDoor (mqtt-bird-agent 0.1.0) | Windows backdoor | `cplsupport.exe`; C2 via HiveMQ public MQTT broker (`broker.hivemq.com`); ChaCha20-Poly1305 encrypted config; runs as Windows service |
| GSocket | Reverse shell | Open-source reverse shell tool used as supplementary C2 access path; unexpected GSocket binaries on endpoints are a hunt indicator |
| Evil-WinRM | Lateral movement | Open-source WinRM tooling used post-credential for lateral movement and implant staging |

## Threat Actor / Campaign Attribution

- **Threat Actor**: Feral Wolf (also known as Toy Ghouls)
- **Motivation**: Financially motivated — ransomware deployment for extortion after prolonged dwell using low-profile messaging C2
- **Targeting**: Russian organizations in retail, construction, manufacturing, and IT
- **Campaign period**: May–August 2026
- **Disclosure**: September 2026 (Kaspersky/Securelist and BI.ZONE)
- **Novel TTPs**: Multi-month dwell using messaging-protocol C2 (MQTT/Matrix) that blends with legitimate traffic, followed by cross-platform ransomware deployment targeting ESXi alongside Windows and Linux

## Associated Threat Actors

| Actor | Alias | References |
|-------|-------|------------|
| Feral Wolf | Toy Ghouls | [Securelist: Toy Ghouls backdoors (Sep 7, 2026)](https://securelist.com/toy-ghouls-new-hivemq-and-element-backdoors/121270/); [Securelist: GenieLocker](https://securelist.com/genielocker-ransomware-for-windows-linux-and-esxi/120843/) |

## Splunk Detection Searches

See `2026-09-07_securelist-toy-ghouls-hivemq-element-backdoors.md` for MatrixDoor and MQTTDoor backdoor detection queries.
See `detections/impact/genielocker_cross_platform_ransomware.md` for GenieLocker-specific detection.

### 1 — Feral Wolf Infrastructure: IP IOC Hit (Network)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest="45.151.45.31"
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app All_Traffic.bytes_out
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src dest dest_port app bytes_out
```

**Risk Score**: 90 (Critical) — Direct IOC match for known Feral Wolf/GenieLocker campaign infrastructure.

### 2 — GSocket Reverse Shell Detection (Endpoint)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("gsocket","gs-netcat","gs-sftp","gs-full-pipe")
     OR Processes.process="*gsocket*"
     OR Processes.process="*gs-netcat*"
  by Processes.dest Processes.user Processes.process_name Processes.process_path
     Processes.process Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user process_name process_path parent_process_name
```

**Risk Score**: 80 (High) — GSocket is a legitimate open-source tool used by Feral Wolf for C2; unexpected on enterprise endpoints.

### 3 — GenieLocker Mass File Encryption — Volume-Based Detection (Endpoint)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.action=modified
  by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_id _time span=1m
| `drop_dm_object_name(Filesystem)`
| stats max(count) as max_per_min by dest user process_name process_id
| where max_per_min > 200
| eval risk_score=case(max_per_min > 1000, 95, max_per_min > 500, 88, max_per_min > 200, 75, true(), 60)
| where risk_score >= 75
| table dest user process_name process_id max_per_min risk_score
```

**Risk Score**: 75–95 (High–Critical) — More than 200 file modifications per minute per process is a strong indicator of active ransomware encryption.

## References

- [Securelist: New GenieLocker ransomware for Windows, ESXi, and Linux](https://securelist.com/genielocker-ransomware-for-windows-linux-and-esxi/120843/)
- [The Hacker News: Three Threat Groups Target Russian Enterprises With Backdoors, Ransomware, and Wipers](https://thehackernews.com/2026/09/three-threat-groups-target-russian.html)
- [GBHackers: Feral Wolf Hackers Exploit Confluence and 1C to Deploy GenieLocker Ransomware](https://gbhackers.com/genielocker-ransomware/)
- [Securelist: Prior Toy Ghouls backdoor research (Sep 7, 2026)](https://securelist.com/toy-ghouls-new-hivemq-and-element-backdoors/121270/)
- [MITRE ATT&CK T1486 — Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [CVE-2023-22515 — Atlassian Confluence Broken Access Control](https://nvd.nist.gov/vuln/detail/CVE-2023-22515)
- [Prior tracking: 2026-09-07_securelist-toy-ghouls-hivemq-element-backdoors.md]
