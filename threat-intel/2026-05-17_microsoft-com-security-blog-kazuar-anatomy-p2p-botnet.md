---
scraped_at: 2026-05-17T00:00:00Z
source_url: https://www.microsoft.com/en-us/security/blog/2026/05/14/kazuar-anatomy-of-a-nation-state-botnet/
report_type: threat-intel
severity: critical
title: "Turla/Secret Blizzard Transforms Kazuar Backdoor Into Modular P2P Botnet"
---

## 1. IOCs

### File Hashes (SHA-256)

| Hash | Description |
|------|-------------|
| `69908f05b436bd97baae56296bf9b9e734486516f9bb9938c2b8752e152315d4` | Kazuar Loader DLL (`_hpbprndiLOC.dll`) — Pelmeni dropper-delivered first-stage loader |
| `c1f278f88275e07cc03bd390fe1cbeedd55933110c6fd16de4187f4c4aaf42b9` | Kazuar Kernel Module — botnet leader election and task orchestration |
| `6eb31006ca318a21eb619d008226f08e287f753aec9042269203290462eaa00d` | Kazuar Bridge Module — external C2 relay and data exfiltration |
| `436cfce71290c2fc2f2c362541db68ced6847c66a73b55487e5e5c73b0636c85` | Kazuar Worker Module — data collection, keylogging, filesystem harvesting |

### Domains / IPs

No external network IOCs published in the Microsoft report. C2 infrastructure overlaps with ORB networks tracked internally by Microsoft Threat Intelligence. Detection relies on behavioral indicators (see Section 5).

### File Paths / Registry Artifacts

- Mailslot IPC: `\\.\mailslot\<MD5-hash-derived-name>`
- Named pipe IPC: `\\.\pipe\<MD5("pipename-kernel-<version>")>`
- Unauthorized SSH authorized_keys modifications (post-compromise lateral indicator)

---

## 2. TTPs

| MITRE Tactic | Technique ID | Technique Name | Usage |
|---|---|---|---|
| Persistence | T1547 | Boot or Logon Autostart Execution | Persistence via PowerShell profile or COM object registration |
| Persistence | T1547.013 | PowerShell Profile | Loader installed as PowerShell profile for auto-execution |
| Defense Evasion | T1140 | Deobfuscate/Decode Files or Information | Pelmeni dropper AES-decrypts payload; binding decryption to target hostname prevents sandbox detonation |
| Defense Evasion | T1562.001 | Impair Defenses: Disable or Modify Tools | AMSI bypass, WLDP bypass, ETW bypass built into Kernel module |
| Defense Evasion | T1027 | Obfuscated Files or Information | Protobuf-serialized IPC messages; modular architecture separates footprint |
| Collection | T1056.001 | Input Capture: Keylogging | KEYL thread captures keystrokes and forwards to Kernel |
| Collection | T1113 | Screen Capture | PEEP thread captures screenshots per configuration schedule |
| Collection | T1056.004 | Input Capture: Credential API Hooking | MAPI email monitoring for credentials and sensitive content |
| Collection | T1083 | File and Directory Discovery | GFIL filesystem harvester with pattern-based file collection |
| Collection | T1010 | Application Window Discovery | GHOO window hook captures window titles and content |
| Discovery | T1082 | System Information Discovery | Comprehensive OS/hardware/software enumeration at infection |
| Discovery | T1016 | System Network Configuration Discovery | Network adapter, ARP table, DNS cache, WSUS enumeration |
| Discovery | T1049 | System Network Connections Discovery | Active connections, RDP hints, ARP enumeration |
| Discovery | T1518.001 | Software Discovery: Security Software Discovery | Enumerates installed AV, AMSI providers, AppLocker settings |
| Discovery | T1087 | Account Discovery | Local user and logon session enumeration |
| Discovery | T1120 | Peripheral Device Discovery | USB device enumeration |
| Command and Control | T1090 | Proxy | Kernel leader acts as P2P relay; non-leaders communicate only internally |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | HTTP transport for C2 communications |
| Command and Control | T1071.003 | Application Layer Protocol: Mail Protocols | Exchange Web Services (EWS) email-based C2 |
| Command and Control | T1008 | Fallback Channels | HTTP → WSS → EWS fallback C2 transport chain |
| Command and Control | T1570 | Lateral Tool Transfer | Module propagation across P2P network nodes |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | Staged data forwarded through Bridge module to C2 |
| Exfiltration | T1197 | BITS Jobs | BITS abused for data exfiltration |

---

## 3. Malware & Tools

### Kazuar P2P Botnet (evolved)

Kazuar is a long-running Turla backdoor originally discovered circa 2017, now significantly re-architected as a modular P2P botnet. The evolved version separates functionality across three module types deployed on every infected host:

**Kernel Module**
- Conducts botnet leader election using an uptime-based algorithm (work = uptime / reboots)
- Elected leader is the sole node that communicates with C2 infrastructure
- Manages task distribution to Worker modules via IPC (Window Messaging, Mailslot, or Named Pipes)
- Stages collected data locally before forwarding through Bridge

**Bridge Module**
- Acts as the external communications interface for the elected Kernel leader
- Supports HTTP, WebSocket Secure (WSS), and Exchange Web Services (EWS) transports
- Proxies exfiltration from Kernel to C2

**Worker Module**
- Executes operator-assigned tasks
- Sub-components: Task Solver, Peep (window hooking), Keylogger, Filesystem gatherer (GINFO, GFIL, GHOO, GMAP)
- Targets documents, PDFs, email content flagged as "politically important"

**Pelmeni Dropper**
- Delivers Kazuar loader as encrypted byte array embedded within the dropper binary
- Payload decryption bound to target hostname — sandbox-resistant
- Deploys lightweight COM-registered loader plus decrypted in-memory payload

**Configuration System**
- 150+ configurable options including AMSI/WLDP/ETW bypass toggles, task scheduling, exfiltration timing/chunking, process injection settings, and file collection patterns
- Working-hours blending: default 08:00–20:00 send window, weekend suppression configurable
- Anti-analysis checks: running process inspection, canary file detection, sandbox DLL identification

---

## 4. Threat Actor / Campaign Attribution

| Attribute | Value |
|---|---|
| Actor | Secret Blizzard (formerly Krypton) |
| Aliases | Turla, VENOMOUS BEAR, Uroburos, Snake, Blue Python, Iron Hunter, Pensive Ursa, Waterbug, SUMMIT, ATG26, WRAITH |
| State Sponsor | Russia — FSB Center 16 (Signals Intelligence / CNO) |
| MITRE Group | [G0010 — Turla](https://attack.mitre.org/groups/G0010/) |
| Targets | Foreign affairs ministries, embassies, government offices, defense departments, defense contractors — primarily Europe, Central Asia, Ukraine |
| Intelligence Focus | Long-term persistent access; collection of documents, PDFs, email content of political/military significance |

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path IN ("*\\\\mailslot\\*","*pipename-kernel*","*_hpbprndiLOC.dll*")
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_name,"(?i)_hpbprndiLOC"), 95,
    match(file_path,"(?i)pipename-kernel"), 85,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user file_path file_name risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process IN ("*powershell*profile*","*register-object*","*comsvcs*","*BITS*")
    AND Processes.parent_process_name IN ("powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","regsvr32.exe")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process,"(?i)powershell.*profile"), 90,
    match(process,"(?i)register-object"), 85,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.app IN ("exchange","ews","http","https")
    AND (All_Traffic.dest_port IN (443,80,587,993,995))
  by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app
     All_Traffic.bytes_out
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| stats sum(bytes_out) as total_bytes_out count as connections dc(dest_ip) as unique_dests
    by src_ip app firstTime lastTime
| eval risk_score=case(
    app="ews" AND total_bytes_out > 10485760, 85,
    connections > 100 AND unique_dests < 3, 80,
    1=1, 60)
| where risk_score >= 80
| table firstTime lastTime src_ip app connections unique_dests total_bytes_out risk_score
```

```spl
index=* (source="/var/log/auth.log" OR source="*auth.log*")
"Accepted publickey for vmanage-admin"
| rex field=_raw "from (?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
| stats count min(_time) as firstTime max(_time) as lastTime by host src_ip
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime host src_ip count risk_score
```

---

## 6. Executive Summary

On May 14, 2026, Microsoft published a detailed technical analysis of Kazuar, a long-running backdoor operated by Turla (Secret Blizzard), Russia's FSB Center 16. The new Kazuar architecture represents a significant operational evolution: the malware now deploys as a modular P2P botnet across infected hosts, with Kernel, Bridge, and Worker modules dividing reconnaissance, communications, and data collection responsibilities.

The P2P design dramatically reduces detection surface — only a single elected "leader" Kernel node communicates with external C2 infrastructure, while all other infected hosts operate in silent mode, limiting network telemetry indicators. The botnet supports 150+ configuration options and multiple C2 transport protocols (HTTP, WebSocket, Exchange Web Services) to blend into enterprise network traffic.

Four file hashes for core Kazuar components were published by Microsoft. No external network IOCs (IPs/domains) were released in this report. Detection relies on behavioral indicators: anomalous PowerShell profile usage for persistence, unusual IPC artifacts (named pipes, mailslots), high-privilege process injection, AMSI/ETW bypass attempts, and EWS-based outbound data flows inconsistent with baseline email volume.

Organizations should audit PowerShell profile files, COM object registrations, and named pipe activity on Windows endpoints. EDR-level process injection detection and mail flow monitoring for anomalous EWS data volumes are key detection controls.
