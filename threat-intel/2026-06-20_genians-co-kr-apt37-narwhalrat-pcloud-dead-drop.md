---
scraped_at: 2026-06-20T00:00:00Z
source_url: https://www.genians.co.kr/en/blog/threat_intelligence/narwhalrat
report_type: threat-intel
severity: high
title: "APT37 (ScarCruft) NarwhalRAT: Microsoft-Themed Phishing Delivers Compiled Python RAT via pCloud Dead-Drop C2"
---

## 1. IOCs

No file hashes were available from accessible sources. IOCs are limited to behavioral and infrastructure patterns described in the Genians analysis.

### C2 Infrastructure Pattern

| Indicator | Type | Notes |
|-----------|------|-------|
| `api.pcloud.com` | Dead-drop resolver domain | Legitimate pCloud API; APT37 abuses it as a dead-drop resolver — attacker pre-positions second-stage C2 URL in an attacker-controlled pCloud file, which the malware fetches on first contact |
| Korean relay server (IP not published) | C2 relay | Dual C2 structure: primary communication relayed through a compromised/attacker-controlled Korean server to blend with domestic Korean traffic patterns |

### File Indicators (Behavioral)

| File Name / Pattern | Context |
|--------------------|---------|
| `config.cat` | NarwhalRAT payload disguised with `.cat` extension (Windows security catalog) — actually compiled Python bytecode (PyInstaller or Nuitka) |
| LNK files with double-extension | Delivery vector; masquerades as document |

### Email Lure

Subject: `[Urgent] Security Check Notice Regarding Repeated One-Time Password (OTP) Generation`
Sender spoofed as: Microsoft Account Team (non-Microsoft domain)

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1566.001 | Phishing: Spearphishing Attachment | Microsoft-themed spearphishing email with malicious LNK attachment |
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | LNK triggers PowerShell to download and execute next stage |
| Execution | T1059.006 | Command and Scripting Interpreter: Python | NarwhalRAT is compiled Python; runtime loaded into memory |
| Execution | T1204.002 | User Execution: Malicious File | User opens LNK file triggering infection |
| Defense Evasion | T1027 | Obfuscated Files or Information | Payload file uses `.cat` extension to mimic Windows security catalog |
| Defense Evasion | T1027.001 | Obfuscated Files or Information: Binary Padding | Environment variable obfuscation in BAT stage |
| Defense Evasion | T1055 | Process Injection | Python runtime RWX memory allocation for in-memory payload execution |
| Persistence | T1053.005 | Scheduled Task/Job: Scheduled Task | Scheduled task creation for persistence across reboots |
| Command and Control | T1102.001 | Web Service: Dead Drop Resolver | pCloud API used to deliver second-stage C2 URL; attacker updates URL without changing malware |
| Command and Control | T1090.001 | Proxy: Internal Proxy | Korean relay server used as traffic relay to blend C2 traffic with domestic patterns |
| Collection | T1056.001 | Input Capture: Keylogging | NarwhalRAT keylogger capability (one of 30+ functions) |
| Collection | T1113 | Screen Capture | Screen capture capability |
| Collection | T1123 | Audio Capture | Microphone recording capability |
| Collection | T1025 | Data from Removable Media | USB drive file collection |
| Execution | T1106 | Native API | Direct API calls for process execution |

---

## 3. Malware & Tools

**NarwhalRAT** — Compiled Python-based remote access trojan attributed to APT37 (ScarCruft / Reaper / InkySquid). The payload is distributed as `config.cat` — a compiled Python bytecode file named with a `.cat` extension to mimic Windows security catalog files. NarwhalRAT supports 30+ remote control functions including:

- Keylogging
- Screen capture
- Microphone and audio recording
- USB storage file collection and exfiltration
- Remote shell execution
- File upload/download
- Scheduled task management
- Process listing and termination

**C2 Architecture:** Dual-channel design:
1. **Dead-drop resolver:** Malware contacts attacker-controlled pCloud account via `api.pcloud.com` to retrieve the live C2 server address. This allows the operator to change C2 infrastructure without redeploying malware.
2. **Korean relay:** Active C2 traffic is relayed through a Korean relay server, making network traffic appear to originate within South Korea.

**Delivery chain:**
```
Spearphishing email
  → Malicious LNK file (double-extension, masquerades as document)
    → PowerShell execution
      → BAT script with env-variable obfuscation
        → Download config.cat (compiled Python payload)
          → Python runtime loaded (RWX memory allocation)
            → NarwhalRAT active
              → Contact api.pcloud.com (dead-drop resolver)
                → Retrieve live C2 server address
                  → Connect to Korean relay C2
```

---

## 4. Threat Actor / Campaign Attribution

**APT37 / ScarCruft (MITRE G0067)** — North Korean state-sponsored threat group, assessed to operate under the Reconnaissance General Bureau (RGB). Primarily targets South Korean government entities, military organizations, journalists, defectors, and human rights activists. Known for persistent evolution of tooling and use of legitimate cloud services (Dropbox, pCloud, OneDrive) as dead-drop resolvers to evade network-based detections.

The NarwhalRAT campaign uses Microsoft Account Team impersonation to target Korean recipients, consistent with APT37's history of impersonating trusted organizations. The pCloud dead-drop pattern is an evolution of APT37's prior Dropbox-based dead-drop C2 (AppleseedRAT, ROKRAT clusters).

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_host="api.pcloud.com"
  AND All_Traffic.app NOT IN ("chrome","firefox","msedge","safari","iexplore","brave","opera")
by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.app All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    All_Traffic.app IN ("powershell","cmd","wscript","cscript","python","python3","mshta","regsvr32"), 85,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime src dest dest_host app dest_port risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name IN ("powershell.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe")
  AND Processes.parent_process_name IN ("WINWORD.EXE","EXCEL.EXE","POWERPNT.EXE","OUTLOOK.EXE","explorer.exe")
by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_name="*.cat"
  AND Filesystem.file_path IN ("*\\AppData\\*","*\\Temp\\*","*\\ProgramData\\*","*\\Users\\*\\Downloads\\*")
by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=50
| table firstTime lastTime dest user file_path file_name process_name risk_score
```

---

## 6. Executive Summary

Genians Security Center published analysis on June 18–19, 2026 of a new APT37 (ScarCruft) campaign deploying NarwhalRAT — a compiled Python remote access trojan — against South Korean targets via Microsoft Account Team-themed spearphishing. The attack chain uses a malicious LNK file to trigger a PowerShell/BAT execution chain that downloads and executes the payload (`config.cat`, disguised as a Windows security catalog file).

NarwhalRAT's most notable characteristic is its dual C2 architecture: a pCloud API dead-drop resolver that stores the live C2 server address (allowing operator flexibility without redeploying malware), combined with a Korean relay server that makes C2 traffic blend with domestic South Korean network patterns. The RAT supports 30+ capabilities including keylogging, screen capture, microphone recording, USB data collection, and remote shell access.

This campaign represents an evolution of APT37's established pattern of leveraging legitimate cloud services (previously Dropbox) as dead-drop resolvers to defeat network-based C2 detections.

**Immediate actions:** Block or monitor non-browser process connections to `api.pcloud.com`. Implement behavioral detection for Office applications spawning PowerShell/CMD. Alert on `.cat` file writes to user-writable paths from unexpected processes.
