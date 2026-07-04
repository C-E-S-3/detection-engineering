---
scraped_at: "2026-07-04T00:00:00Z"
source_url: "https://securelist.com/armored-likho-apt-with-busysnake-stealer/120292/"
report_type: threat-intel
severity: high
title: "Armored Likho (Eagle Werewolf): BusySnake Python Stealer with Go2Tunnel Targeting Government and Power Sector"
---

# Armored Likho (Eagle Werewolf): BusySnake Python Stealer with Go2Tunnel Targeting Government and Power Sector

**Source:** Kaspersky GReAT / Securelist (report 120292)  
**Published:** 2026-07-03  
**Severity:** High  
**Tactic:** Credential Access (TA0006), Collection (TA0009), Exfiltration (TA0010), Persistence (TA0003)

---

## 1. IOCs

No specific file hashes, C2 domains, or IP addresses are available from open-source coverage. Full IOC set (SHA-256 hashes, C2 infrastructure, GitHub payload repository names) is gated behind the Kaspersky Threat Intelligence Portal (https://tip.kaspersky.com) under report 120292.

**Behavioral indicators (available from open sources):**

| Indicator | Type | Context |
|-----------|------|---------|
| `WindowsHelper` | Scheduled task name | BusySnake persistence task; created via VBScript (v1) or `win32com.client` Schedule.Service COM object (v2) |
| `MicrosoftOfficeUpdate` | Scheduled task name | AquilaRAT (Eagle Werewolf/related cluster) persistence task |
| `.pyw` | File extension | BusySnake stealer executable format; Python windowed — runs without spawning a console |
| `python.exe` / embedded Python runtime | Process name | BusySnake executes via embedded Python runtime; watch for python spawning from user AppData paths |

---

## 2. TTPs

| MITRE Technique | ID | Description |
|-----------------|----|-------------|
| Spearphishing Attachment | T1566.001 | RAR archive containing EXE dropper or LNK file; government notice and social program lure themes |
| User Execution: Malicious File | T1204.002 | Victim opens RAR archive and executes EXE dropper or LNK |
| Command and Scripting Interpreter: PowerShell | T1059.001 | LNK chain triggers PowerShell to pull second-stage payload |
| Command and Scripting Interpreter: Visual Basic | T1059.005 | VBScript files dropped for trace cleanup (v1) and scheduled task registration (v1) |
| Command and Scripting Interpreter: Python | T1059.006 | BusySnake is Python-based; packaged as `.pyw` to suppress console window |
| Scheduled Task/Job: Scheduled Task | T1053.005 | `WindowsHelper` task persists BusySnake; v2 uses COM-based registration via Schedule.Service |
| Obfuscated Files or Information | T1027 | PyArmor Pro 9.2.0 bytecode encryption — decrypts per-function call, immediately re-encrypts; defeats static analysis |
| Screen Capture | T1113 | Periodic screenshot capture at configurable interval; archives and exfiltrates |
| Input Capture: Keylogging | T1056.001 | Keystroke logging module |
| Data from Local System | T1005 | File enumeration logged to local SQLite; documents uploaded to C2 |
| Clipboard Data | T1115 | Clipboard contents stolen |
| File and Directory Discovery | T1083 | Filesystem enumeration with metadata logging |
| Archive Collected Data | T1560 | Screenshots archived before exfiltration |
| Exfiltration Over C2 Channel | T1041 | Documents, screenshots, credentials, and wallet files exfiltrated to C2 |
| Credentials from Password Stores: Web Browser | T1555.003 | Saved passwords and cookies extracted from Firefox and Chromium-based browsers |
| Steal Web Session Cookie | T1539 | Browser cookie module included in at least one BusySnake version |
| Unsecured Credentials: Credentials in Files | T1552.001 | Telegram session data and credential files harvested |
| Protocol Tunneling | T1572 | Go2Tunnel establishes reverse SSH tunnel to C2; parameters (including SSH private key) supplied by C2 |
| Remote Services: SSH | T1021.004 | SSH tunnel via Go2Tunnel for operator remote access |
| Remote Access Software | T1219 | RustDesk installed or invoked; credentials captured via screenshot as victim enters them |
| Valid Accounts | T1078 | RustDesk credentials captured for persistent remote access |
| Ingress Tool Transfer | T1105 | BusySnake payload pulled from GitHub repository by dropper |
| Exploit Public-Facing Application (CVE-2025-9491) | T1190 | LNK chain exploits Windows shortcut hidden-argument vulnerability (patched November 2025) |

---

## 3. Malware & Tools

### BusySnake Stealer

- **Language:** Python  
- **Extension:** `.pyw` (windowed; no console)  
- **Obfuscation:** PyArmor Pro 9.2.0 — bytecode dynamically decrypted per-function, then re-encrypted immediately; defeats static analysis and most sandboxes  
- **C2 polling:** `poll_task` function loops continuously, sends machine identifier to C2, receives task parameters  
- **Configuration stored in malware:** C2 URL, directory paths, regex patterns, screenshot interval, HTTP User-Agent string

**Capability set (C2-command-driven):**

| Capability | Description |
|-----------|-------------|
| Clipboard theft | Steal current clipboard contents |
| File enumeration | Log file metadata to local SQLite database |
| Document upload | Exfiltrate matching documents to C2 |
| Screenshot capture | Periodic screenshots at configured interval; archived and deleted after exfil |
| Keylogging | Keystroke capture module |
| Cryptocurrency wallet theft | Targets `.json` wallet files |
| Telegram credential theft | Extracts Telegram session data and stored credentials |
| Go2Tunnel (built-in) | Receive tunnel parameters from C2; establish reverse SSH tunnel |
| RustDesk abuse | Install if absent, launch, screenshot victim-entered credentials, exfiltrate |
| Browser cookie theft | Mozilla Firefox and Chromium-based browser cookies (dedicated module, some versions) |
| Browser password theft | Saved passwords from Firefox and Chromium |
| Anti-concurrent-instance check | Prevents multiple instances running |
| Persistence check | Verify/create `WindowsHelper` scheduled task |

**Persistence mechanisms:**  
- v1: Drops two VBScript files — one cleans up initial execution traces, one registers `WindowsHelper` scheduled task  
- v2: Uses `win32com.client` / `Schedule.Service` COM object to create `WindowsHelper` task; no VBScript file on disk

### Go2Tunnel

- **Language:** Go  
- **Purpose:** Reverse SSH tunnel to C2 server  
- **Original form:** Standalone utility; now integrated into BusySnake as built-in module  
- **Operation:** C2 returns full SSH tunnel parameters including private key and complete SSH command string; stealer executes the tunnel

### AquilaRAT (Eagle Werewolf cluster, related)

- **Language:** Rust  
- **Dropper:** Rust binary masquerading as Starlink device activation checklist  
- **Distribution:** Trojanized Telegram channel (drone-focused community), February 2026  
- **Persistence task:** `MicrosoftOfficeUpdate`  
- **Overlap with BusySnake:** Similar C2 task-receipt mechanism, scheduled-task persistence, and C2 endpoint patterns

---

## 4. Infection Chains

**Chain A — EXE Dropper (earlier campaigns):**
```
Spear-phishing email (government notice / social program lure)
  └→ RAR archive attachment
       └→ EXE dropper
            ├→ Fetches BusySnake from attacker-controlled GitHub repository
            ├→ Drops VBScript #1 (trace cleanup — removes dropper artifacts)
            └→ Drops VBScript #2 → registers WindowsHelper scheduled task → launches BusySnake
```

**Chain B — LNK / CVE-2025-9491 (newer campaigns):**
```
Spear-phishing email
  └→ RAR archive
       └→ .LNK file (exploits CVE-2025-9491 — Windows shortcut hidden-argument UI misrepresentation)
            └→ rundll32.exe executes obfuscated command
                 └→ PowerShell pulls second-stage payload from attacker infrastructure
                      ├→ Displays decoy document (matching lure theme)
                      └→ Prepares Python environment → executes BusySnake
```

**CVE-2025-9491:** Windows LNK file vulnerability allowing hidden command-line arguments not visible in the shortcut's Properties dialog; victim sees a benign-looking shortcut, but double-clicking executes attacker's hidden payload. Patched in Microsoft November 2025 Patch Tuesday.

---

## 5. Threat Actor Profile

| Attribute | Detail |
|-----------|--------|
| Kaspersky designation | Armored Likho |
| BI.ZONE designation | Eagle Werewolf |
| Active since | May 2023 (Eagle Werewolf cluster) |
| Motivation | Hybrid: cyber-espionage + financially motivated campaigns targeting private individuals |
| Primary targets | Government agencies, electric power sector |
| Geographic focus | Russia, Kazakhstan, Brazil |
| Tradecraft | Obfuscated, modular Python infostealers/RATs designed to bypass dynamic analysis; stable distribution method (spear-phishing → RAR) with evolving payload and persistence mechanisms |
| Cluster relationship | Armored Likho and Eagle Werewolf share TTP overlaps but BI.ZONE notes "no evidence of direct coordination"; may be loosely affiliated or sharing tooling independently |

---

## 6. Splunk Detection Searches

```spl
`sysmon` EventCode=1
  (ParentImage="*\\python.exe" OR ParentImage="*\\pythonw.exe")
  (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\net.exe"
   OR Image="*\\reg.exe" OR Image="*\\schtasks.exe")
| stats count min(_time) as firstTime max(_time) as lastTime by host user ParentImage Image CommandLine
| eval risk_score=85
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime host user ParentImage Image CommandLine risk_score
```

```spl
index=wineventlog EventCode=4698
  (TaskName="*WindowsHelper*" OR TaskName="*MicrosoftOfficeUpdate*")
| stats count by Computer SubjectUserName TaskName TaskContent
| eval risk_score=80
| table _time Computer SubjectUserName TaskName risk_score
```

```spl
`sysmon` EventCode=1
  Image="*\\mshta.exe" OR Image="*\\wscript.exe" OR Image="*\\cscript.exe"
  CommandLine="*.pyw*"
| stats count min(_time) as firstTime max(_time) as lastTime by host user Image CommandLine
| eval risk_score=75
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime host user Image CommandLine risk_score
```

---

## 7. Executive Summary

Kaspersky GReAT published research on July 3, 2026 documenting Armored Likho — a previously unreported APT group (also tracked as Eagle Werewolf by BI.ZONE) targeting government agencies and the electric power sector across Russia, Kazakhstan, and Brazil since May 2023.

The group's primary tool is BusySnake, a Python-based infostealer protected by PyArmor Pro 9.2.0 bytecode encryption (which defeats static analysis by decrypting code per-function-call and re-encrypting immediately). BusySnake implements an unusually broad capability set including clipboard theft, keylogging, browser credential/cookie harvesting, cryptocurrency wallet theft, Telegram session extraction, and reverse SSH tunneling via an integrated Go2Tunnel module. A unique capability is RustDesk abuse: BusySnake installs or launches RustDesk on the victim machine, then screenshots the credentials the victim enters — enabling persistent remote access without deploying a traditional RAT.

Initial access is achieved via spear-phishing RAR archives using government notice or social program lures. Newer campaigns use CVE-2025-9491 (Windows LNK hidden-argument vulnerability, patched November 2025) to execute malicious commands without a visible command prompt, improving detection evasion. The payload is pulled from attacker-controlled GitHub repositories.

Full IOC set (file hashes, C2 domains/IPs, GitHub repository names) requires Kaspersky TIP subscription access.

---

## References

- [Securelist — Armored Likho's New Weapon: BusySnake Stealer (2026-07-03)](https://securelist.com/armored-likho-apt-with-busysnake-stealer/120292/)
- [The Hacker News — Armored Likho Targets Government Agencies, Power Sector](https://thehackernews.com/2026/07/armored-likho-targets-government.html)
- [BI.ZONE — Unholy Trinity: Werewolves Target Law Enforcers (Eagle Werewolf)](https://bi.zone/eng/expertise/blog/triedinoe-zlo-oborotni-atakuyut-sotrudnikov-silovykh-struktur/)
- [NVD — CVE-2025-9491 (Windows LNK Hidden Arguments)](https://nvd.nist.gov/vuln/detail/CVE-2025-9491)
- [MITRE ATT&CK — T1566.001: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- [MITRE ATT&CK — T1053.005: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
- [MITRE ATT&CK — T1572: Protocol Tunneling](https://attack.mitre.org/techniques/T1572/)
- [Kaspersky Threat Intelligence Portal — Report 120292](https://tip.kaspersky.com)
