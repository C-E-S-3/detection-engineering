---
scraped_at: 2026-10-31T00:00:00Z
source_url: https://blog.talosintelligence.com/nik-c2-ai-integrated-command-and-control/
report_type: threat-intel
severity: high
title: "NIK C2: AI-Integrated Windows Command-and-Control Framework"
---

# NIK C2: AI-Integrated Windows Command-and-Control Framework

**Date:** 2026-10-29 (Talos publication)
**Source:** Cisco Talos Intelligence Group
**Threat Type:** Windows RAT / C2 Framework
**Platform:** Windows
**Attribution:** Unknown; no APT attribution at time of writing

---

## Executive Summary

Cisco Talos published analysis of NIK C2, a Go-based Windows remote access trojan that abuses the victim's own `OPENAI_API_KEY` environment variable to authenticate requests to OpenAI's API as part of its operational workflow. The RAT establishes a primary WebSocket C2 channel over TLS on port 443; the attacker-controlled server presents a TLS certificate with CN `nik-panel`. A secondary HTTP fallback polls the C2 at 250ms intervals. Capabilities include credential dumping, keylogging, RDP session hijacking, and a screen-locking ransomware-style extortion module that locks the desktop without encrypting files. The combination of WebSocket TLS C2 with AI API abuse as a fingerprinting/capability mechanism represents a new pattern not previously documented in open-source reporting.

---

## 1. Indicators of Compromise (IOCs)

### Network

| Type | Indicator | Context |
|------|-----------|---------|
| Domain | `total-sitevv[.]lol` | NIK C2 primary C2 domain |
| IP | `87.120.196[.]120` | NIK C2 C2 server hosting total-sitevv[.]lol |
| TLS CN | `nik-panel` | Server certificate Common Name on NIK C2 WebSocket endpoint |
| Port | TCP/443 (WSS) | Primary WebSocket C2 channel |
| URI | `HTTP /poll` | HTTP fallback polling endpoint; 250ms polling interval |

### Behavioral

- Non-browser process opens WebSocket connection to external host on TCP/443
- Same process is observed making HTTPS requests with `Authorization: Bearer <OPENAI_API_KEY>` to `api.openai.com`
- Screen-lock invocation without accompanying ransomware encryption activity
- New process spawned from the implant performing `vssadmin` or `lsass` memory access (credential dumping)

---

## 2. TTPs (MITRE ATT&CK Mapping)

| Tactic | Technique | Description |
|--------|-----------|-------------|
| Command and Control (TA0011) | T1071.001 — Application Layer Protocol: Web Protocols | Primary WebSocket-over-TLS C2 on port 443 |
| Command and Control (TA0011) | T1573.001 — Encrypted Channel: Symmetric Cryptography | TLS-encrypted WebSocket channel with attacker-controlled certificate |
| Command and Control (TA0011) | T1008 — Fallback Channels | HTTP polling at 250ms as fallback when WebSocket unavailable |
| Command and Control (TA0011) | T1102 — Web Service | Abuses victim's OPENAI_API_KEY to interact with OpenAI API; attacker leverages victim's AI service access |
| Credential Access (TA0006) | T1003.001 — OS Credential Dumping: LSASS Memory | Credential dumping capability targeting LSASS process |
| Collection (TA0009) | T1056.001 — Input Capture: Keylogging | Keylogging capability in implant |
| Lateral Movement (TA0008) | T1563.002 — Remote Service Session Hijacking: RDP Hijacking | RDP session hijacking module |
| Impact (TA0040) | T1491.001 — Defacement: Internal Defacement | Screen-locking extortion module; locks desktop without file encryption |

---

## 3. Malware & Tools

**NIK C2 Implant (Go/Windows)**

- Language: Go (statically compiled Windows PE)
- C2 transport: WebSocket over TLS (port 443); HTTP fallback polling at 250ms
- Server TLS CN: `nik-panel`
- AI API abuse: reads `OPENAI_API_KEY` from victim environment; used to make authorized requests to OpenAI API on behalf of the attacker (exact purpose unclear — likely for tasking, LLM-assisted reconnaissance, or exfiltration staging)
- Credential dumping: targets LSASS memory
- Keylogging: kernel-level or Win32 API-based; exfiltrated to C2
- RDP hijacking: abuses Windows session table manipulation to hijack existing RDP sessions without victim credential
- Screen-locker: replaces desktop shell / sets lock screen; no file encryption observed; extortion message displayed

---

## 4. Threat Actor / Campaign Attribution

No specific threat actor attribution has been made by Talos at time of reporting. The AI API key abuse pattern is novel and may indicate a financially motivated operator targeting developer workstations, research environments, or AI-integrated enterprise systems where `OPENAI_API_KEY` is likely to be present. The screen-locking ransomware-without-encryption module may indicate an operator testing extortion capabilities or targeting victims who lack backups but cannot afford data destruction.

---

## 5. Splunk Detection Opportunities

### 5a. DNS IOC Match

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query IN ("total-sitevv.lol", "*.total-sitevv.lol")
  by DNS.src DNS.query DNS.record_type
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src query record_type
```

### 5b. Non-Browser WebSocket on Port 443 with High Frequency (NIK C2 Pattern)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime dc(All_Traffic.dest) as dest_count
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_port=443 All_Traffic.transport=tcp
  by All_Traffic.src All_Traffic.app _time span=1m
| `drop_dm_object_name(All_Traffic)`
| where app NOT IN ("chrome.exe","firefox.exe","msedge.exe","safari","opera.exe","brave.exe","iexplore.exe")
| stats count avg(count) as avg_per_min by src app
| where avg_per_min > 50
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src app avg_per_min
```

### 5c. AI API Key Abuse by Non-Expected Process

```spl
index=* sourcetype IN ("WinEventLog:Security","XmlWinEventLog:Microsoft-Windows-Sysmon/Operational")
EventCode=1
(CommandLine="*api.openai.com*" OR CommandLine="*OPENAI_API_KEY*")
NOT (Image="*\\msedge.exe" OR Image="*\\chrome.exe" OR Image="*\\firefox.exe"
     OR Image="*\\cursor.exe" OR Image="*\\code.exe" OR Image="*\\python*"
     OR Image="*\\node.exe" OR Image="*\\node.js")
| stats count by Computer User Image CommandLine ParentImage
| table Computer User Image CommandLine ParentImage count
```

---

## 6. References

- [Cisco Talos — NIK C2: AI-Integrated Windows Command-and-Control Framework](https://blog.talosintelligence.com/nik-c2-ai-integrated-command-and-control/)
- [MITRE ATT&CK — T1071.001 Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [MITRE ATT&CK — T1102 Web Service](https://attack.mitre.org/techniques/T1102/)
- [MITRE ATT&CK — T1003.001 OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- [MITRE ATT&CK — T1563.002 Remote Service Session Hijacking: RDP Hijacking](https://attack.mitre.org/techniques/T1563/002/)
