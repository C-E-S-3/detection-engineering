---
scraped_at: 2026-07-14T00:00:00Z
source_url: https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/
report_type: threat-intel
severity: critical
title: "GigaWiper: Anatomy of a Destructive Backdoor Assembled from Multiple Malware (BLUERABBIT)"
---

## 1. IOCs

### File Hashes (SHA256)

| Hash | Description |
|------|-------------|
| `633d4cbd496b1094495da89a64f5e6c31a0f6d4d1488411db5b0cba1cfe42001` | GigaWiper backdoor binary |
| `ce9ad5f6c12019f4aae5b189bd8ddf5bb09e75b06a0a587b25a855c65948c913` | GigaWiper backdoor binary |
| `f622ed85ef31ad4ab973f4e74524866fe1bb44f0965ad2b2ad796cd657a05bfd` | GigaWiper backdoor binary |
| `9706a192e2c1a1faaf0a521daf31c2af60ff4590e3f47bbb4abc227f42af0683` | GigaWiper backdoor binary |
| `3c30deb6556a94cfb84ae51798f4aecfae8c7358e55fdb321c5f2376579631cd` | GigaWiper standalone wiper module |
| `440b5385d3838e3f6bc21220caa83b65cd5f3618daea676f271c3671650ce9a3` | Crucio fake-ransomware component (`.candy` extension) |
| `12c39f052f030a77c0cd531df86ad3477f46d1287b8b98b625d1dcf89385d721` | FlockWiper Go-reimplementation wiper component |
| `db41e0da7ab3305be8d9720769c6950b4dc1c1984ef857d3310eb873a0fc7674` | FlockWiper wiper component |

### IP Addresses (C2)

| IP | Description |
|----|-------------|
| `185.182.193[.]21` | GigaWiper C2 — RabbitMQ AMQP on port 5544, Redis on port 7542 |
| `212.8.248[.]104` | GigaWiper C2 — secondary infrastructure |

### Registry Keys

- `HKCU\SOFTWARE\OneDrive\Environment` — execution-state tracking key written at install time

### File Paths

- `C:\ProgramData\output` — screen recordings and screenshots deposited here before exfiltration
- `./image_danger.jpg` — fake ransomware wallpaper dropped after Crucio encryption

## 2. TTPs

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Execution | T1106 | Native API | Windows API calls for disk I/O and IOCTL driver operations (disk wipe) |
| Persistence | T1053.005 | Scheduled Task/Job: Scheduled Task | Creates `OneDrive Update` scheduled task running every minute and at startup |
| Lateral Movement | T1021.001 | Remote Services: Remote Desktop Protocol | Command 20: VNC-like remote control injecting a firewall allow rule |
| Command and Control | T1571 | Non-Standard Port | RabbitMQ AMQP on port 5544; Redis on port 7542 |
| Collection | T1113 | Screen Capture | Commands 9/10: per-monitor screenshot capture and screen recording when user active |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | Command 4: data upload via MinIO protocol over the RabbitMQ/Redis C2 path |
| Defense Evasion | T1562.001 | Impair Defenses: Disable or Modify Tools | Command 19: clears all Windows event log channels; enumerates Windows Defender exclusions |
| Defense Evasion | T1036.004 | Masquerading: Masquerade Task or Service | Scheduled task named `OneDrive Update` to blend with legitimate Microsoft tasks |
| Discovery | T1082 | System Information Discovery | Command 15: hostname, OS version, disk layout, running software inventory |
| Discovery | T1007 | System Service Discovery | WMI query to enumerate physical drives before wiping |
| Impact | T1561.002 | Disk Wipe: Disk Structure Wipe | Command 1: removes partition metadata via `IOCTL_DISK_CREATE_DISK`, then overwrites all drives in 0xA00000-byte randomized chunks, forcing reboot |
| Impact | T1561.001 | Disk Wipe: Disk Content Wipe | Command 12 (FlockWiper): multi-pass secure erasure (0x00, 0xFF, random bytes) of Windows installation drive |
| Impact | T1486 | Data Encrypted for Impact | Command 3 (Crucio): AES encryption with random, unsaved key/IV; files renamed with `.candy` extension; no decryption possible |
| Impact | T1529 | System Shutdown/Reboot | Forced reboot issued immediately after disk wipe completes |

## 3. Malware & Tools

**GigaWiper** (also tracked as **BLUERABBIT** by Google Threat Intelligence Group and Binary Defense) is a Golang-based Windows backdoor first identified by Microsoft in October 2025 during an incident response engagement involving destructive wiping activity. It consolidates three previously separate malware families into a single versatile implant delivered as an unstripped PE:

- **Crucio** (fake ransomware): Encrypts files with a randomly-generated AES key and IV that are never saved, then appends the `.candy` extension. Functionally a wiper masquerading as ransomware — victim files cannot be recovered.
- **FlockWiper**: Go re-implementation of a C-based wiper (first VirusTotal upload June 2025). Performs multiple overwrite passes (zeros, 0xFF, random bytes) restricted to the Windows installation drive.
- **Physical Disk Wiper**: Enumerates all physical drives via WMI, removes partition metadata using `IOCTL_DISK_CREATE_DISK`, and overwrites the full disk surface with randomized data in 0xA00000-byte chunks before forcing a system reboot.

**C2 architecture:** RabbitMQ AMQP with two exchange types:
- *Fanout exchange* (`All`): broadcasts commands simultaneously to every connected GigaWiper instance (mass wipe scenario)
- *Topic exchange* (`Topic`): targeted commands routed to specific hosts by routing key (selective destruction/espionage)

The configuration block is AES-encrypted with hard-coded credentials embedded in the binary. All 20+ operator commands are dispatched via RabbitMQ; responses flow back through Redis. Screen recordings and screenshots are staged to `C:\ProgramData\output` before upload.

PDB path and function name analysis reveals a shared internal framework referenced as `GRAT`, suggesting GigaWiper, Crucio, and FlockWiper were developed by the same team.

## 4. Threat Actor / Campaign Attribution

Microsoft does not attribute GigaWiper to a specific nation-state in their disclosure. Google Threat Intelligence Group (GTIG) and Binary Defense independently tracked the same malware as **BLUERABBIT** and attributed it to a likely **Iran-nexus** group based on victimology patterns (targeting organizations in Israel, documented from at least March 2026). The Crucio ransomware component was previously referenced in CISA Advisory AA23-335A (December 2023), establishing at least a two-year operational history for the developer behind this toolset.

## 5. Splunk Detection Searches

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
  AND (Processes.process="*OneDrive Update*" AND (Processes.process="*/sc MINUTE*" OR Processes.process="*/sc minute*"))
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

## 6. Executive Summary

Microsoft disclosed GigaWiper on July 9, 2026 — a sophisticated Golang Windows backdoor that combines espionage and multiple destruction modalities in a single operator-dispatched framework. Upon command, GigaWiper can render systems unbootable (disk wipe), destroy data irreversibly (fake ransomware with no recovery key), remotely control hosts via VNC, capture screen video and screenshots, manage services/processes/registry, and erase Windows event logs. The C2 uses RabbitMQ (port 5544) and Redis (port 7542), allowing operators to broadcast destruction commands to all infected hosts simultaneously or target individual machines. Persistence is masqueraded as a legitimate Microsoft task (`OneDrive Update`, 1-minute recurrence). Also tracked as BLUERABBIT by Google GTIG and Binary Defense with probable Iran-nexus attribution based on Israeli targeting. Organizations should immediately alert on outbound connections to non-standard AMQP port 5544 or Redis port 7542, and review schtasks.exe execution creating minute-interval tasks named `OneDrive Update`.

## References

- [Microsoft Security Blog — GigaWiper (2026-07-09)](https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/)
- [The Register — GigaWiper coverage (2026-07-10)](https://www.theregister.com/security/2026/07/10/destructive-windows-backdoor-stuffs-multiple-wipers-and-ransomware-code-into-a-single-package/5270053)
- [The Hacker News — GigaWiper (2026-07-10)](https://thehackernews.com/2026/07/new-gigawiper-windows-backdoor-bundles.html)
- [CISA Advisory AA23-335A — Crucio ransomware (December 2023)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-335a)
- [MITRE ATT&CK T1561.002 — Disk Wipe: Disk Structure Wipe](https://attack.mitre.org/techniques/T1561/002/)
- [MITRE ATT&CK T1486 — Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
