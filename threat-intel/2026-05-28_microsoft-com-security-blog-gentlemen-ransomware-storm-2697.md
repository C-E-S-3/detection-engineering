---
scraped_at: 2026-06-15T00:00:00Z
source_url: https://www.microsoft.com/en-us/security/blog/2026/05/28/the-gentlemen-ransomware-dissecting-a-self-propagating-go-encryptor/
report_type: threat-intel
severity: critical
title: "The Gentlemen Ransomware (Storm-2697): Self-Propagating Go Encryptor with Wormable Lateral Movement"
---

# The Gentlemen Ransomware (Storm-2697): Self-Propagating Go Encryptor with Wormable Lateral Movement

## 1. IOCs

### File Hashes (SHA256)

| Hash | Type | Description |
|------|------|-------------|
| `22b38dad7da097ea03aa28d0614164cd25fafeb1383dbc15047e34c8050f6f67` | SHA256 | Gentlemen ransomware encryptor binary (Go/Garble-obfuscated) |
| `fe1033335a045c696c900d435119d210361966e2fb5cd1ba3382608cfa2c8e68` | SHA256 | Gentlemen wallpaper bitmap (`gentlemen.bmp`) dropped to `%TEMP%` post-encryption |

### Ransomware Artifacts

| Artifact | Type | Description |
|----------|------|-------------|
| `.umc16h` | File extension | Extension appended to all encrypted files |
| `README-GENTLEMEN.txt` | Ransom note | Dropped in every scanned directory; contains victim ID and Tor contact URL |
| `%TEMP%\gentlemen.bmp` | Wallpaper | Desktop background changed to Gentlemen ransom wallpaper post-encryption |

### Persistence Artifacts (Scheduled Tasks)

| Name | Context |
|------|---------|
| `gentlemen_system` | Persistence scheduled task created for SYSTEM-context execution |
| `UpdateSystem` | Scheduled task alias used in staging |
| `DefU`, `UpdateGU`, `UpdateGU2` | Remote target scheduled tasks (user context) during worm spreading |
| `DefSvc`, `UpdateSvc`, `UpdateSvc2` | Remote target scheduled tasks (service context) during worm spreading |

### Registry Persistence Keys

| Key | Description |
|-----|-------------|
| `HKLM\...\GupdateS` | SYSTEM-context Run key for persistence |
| `HKCU\...\GupdateU` | User-context Run key for persistence |

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1190 | Exploit Public-Facing Application | CVE-2024-55591 (FortiOS authentication bypass) used as primary initial access vector per analysis of May 2026 operational leak |
| Execution | T1059.001 | PowerShell | PowerShell remoting (`Invoke-Command`) used during worm spreading phase |
| Execution | T1047 | Windows Management Instrumentation | WMIC `process call create` used for remote execution during spreading |
| Execution | T1569.002 | Service Execution | Remote service creation via `sc` commands during spreading |
| Persistence | T1053.005 | Scheduled Task/Job: Scheduled Task | Dual-layer persistence via scheduled tasks (`gentlemen_system`, `UpdateSystem`) + registry Run keys |
| Persistence | T1547.001 | Registry Run Keys / Startup Folder | Registry Run keys (`GupdateS`, `GupdateU`) for SYSTEM and user contexts |
| Defense Evasion | T1562.001 | Impair Defenses: Disable or Modify Tools | Microsoft Defender real-time monitoring disabled; Defender exclusions added for C:\ and malware path |
| Defense Evasion | T1070.001 | Indicator Removal: Clear Windows Event Logs | System, Application, and Security event logs cleared; PowerShell command history deleted |
| Defense Evasion | T1070.004 | Indicator Removal: File Deletion | Self-deletion batch script (`<malware_path>.bat`) executed post-payload staging |
| Lateral Movement | T1021.006 | Remote Services: Windows Remote Management | WinRM / PowerShell remoting to spread encryptor to remote hosts |
| Lateral Movement | T1570 | Lateral Tool Transfer | Payload copied to `\\<target>\C$\Temp\` via SMB using hidden `share$` share |
| Discovery | T1135 | Network Share Discovery | Enumerates reachable network shares for spread targets |
| Discovery | T1087 | Account Discovery | Credential and account enumeration to support authenticated lateral movement |
| Impact | T1486 | Data Encrypted for Impact | XChaCha20 + Curve25519 ECDH per-file encryption; appends `.umc16h` extension |
| Impact | T1490 | Inhibit System Recovery | Shadow copy deletion via VSS; free space overwrite (`wipefile.tmp`) |
| Impact | T1489 | Service Stop | 40+ services disabled: MSSQL, Exchange, Veeam, virtualization, SAP, EDR agents |

## 3. Malware & Tools

| Tool/Malware | Description |
|--------------|-------------|
| **The Gentlemen** encryptor | Go binary obfuscated with Garble; XChaCha20+Curve25519 per-file encryption; speed variants (default, --fast, --superfast, --ultrafast); worm mode via --spread; hardcoded per-build password via --password flag |
| **PsExec** | Used for remote execution during worm spreading (deposited to `C:\Temp\psexec.exe`) |
| **G-BOT** | Custom C2 framework used by Gentlemen RaaS affiliates; supports per-beacon SOCKS5 tunneling; hosted on temporary file-sharing infrastructure |
| **SystemBC** | SOCKS5 proxy malware used as persistent C2 tunnel; botnet of 1,570+ corporate victims identified in one affiliate's infrastructure |

### Encryption Details

- **Algorithm**: XChaCha20 stream cipher with Curve25519 ECDH key exchange
- **Key model**: Unique ephemeral Curve25519 key pair per file
- **Key storage**: Base64-encoded ephemeral public key appended in file footer
- **Speed modes**: Default (~27% encrypted), --fast (~9%), --superfast (~3%), --ultrafast (~0.9%); files ≤1 MB fully encrypted regardless

### Worm Spreading Chain (8 techniques per target)

The `--spread` argument triggers 21 operations against each target in parallel:
1. SMB file copy to `\\<target>\C$\Temp\`
2. PsExec multi-stage execution
3. WMIC `process call create`
4. Scheduled tasks (user context, 2-minute delay)
5. Scheduled tasks (SYSTEM context)
6. Service creation via `sc`
7. PowerShell remoting (`Invoke-Command` via WinRM)
8. WMI direct execution

A hidden SMB share (`share$`, anonymous access enabled) is created on compromised hosts to allow remote systems to pull the payload without credentials.

## 4. Threat Actor / Campaign Attribution

| Field | Value |
|-------|-------|
| Microsoft Designation | **Storm-2697** |
| Platform Name | "The Gentlemen" |
| Emergence | Mid-2025 (closed group); September 2025 (RaaS transition with BreachForums affiliate recruitment) |
| Administrator | "zeta88" (Russian-speaking, per May 2026 internal leak analysis) |
| Victims | 478+ confirmed across 66 countries and 20+ industry sectors (as of June 2026) |
| Targeted Sectors | Education, Transportation, Healthcare, Financial Services |
| Geographic Reach | North America, South America, Europe, Africa, Asia |
| Operational Model | Double-extortion RaaS; data leak site for non-paying victims |
| Operational Leak | May 4, 2026: Rocket.Chat logs and internal tooling leaked, exposing operator roster, IOCs, and affiliate G-BOT infrastructure |

## 5. Splunk Detection Searches

### Search 1 — Gentlemen Ransomware Scheduled Task Creation

Detects creation of Gentlemen-specific scheduled task names used during initial persistence and worm spreading.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="schtasks.exe"
  AND (Processes.process="*gentlemen_system*"
    OR Processes.process="*UpdateGU2*"
    OR Processes.process="*UpdateSvc2*"
    OR Processes.process="*DefSvc*")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=99
| where risk_score >= 50
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Search 2 — Gentlemen Ransomware Encrypted File Extension Detection

Detects mass creation of `.umc16h` files or the Gentlemen ransom note on endpoints.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where (Filesystem.file_name="*.umc16h" OR Filesystem.file_name="README-GENTLEMEN.txt" OR Filesystem.file_name="gentlemen.bmp")
by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_name, "README-GENTLEMEN\.txt"), 99,
    match(file_name, ".*\.umc16h"), 99,
    1=1, 90)
| where risk_score >= 50
| table firstTime lastTime dest user file_name file_path risk_score
```

### Search 3 — Gentlemen Ransomware Worm: Mass PsExec Lateral Movement to Admin Shares

Detects the worm spreading behavior of PsExec copying payloads to multiple remote C$\Temp\ admin shares.

```spl
| tstats `security_content_summariesonly` count values(Processes.dest) as remote_targets min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="psexec.exe" OR Processes.process_name="psexec64.exe"
  AND Processes.process="*C$*Temp*"
by Processes.src Processes.user Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval remote_count=mvcount(remote_targets)
| where remote_count >= 5
| eval risk_score=case(remote_count >= 20, 95, remote_count >= 10, 85, 1=1, 75)
| table firstTime lastTime src user process_name process remote_targets remote_count risk_score
```

### Search 4 — Gentlemen Ransomware Defense Evasion: Defender Disable + Event Log Clear Combo

Detects the pre-encryption defense evasion sequence of disabling Defender and clearing event logs.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where (Processes.process="*Set-MpPreference*DisableRealtimeMonitoring*"
    OR Processes.process="*wevtutil*cl*System*"
    OR Processes.process="*wevtutil*cl*Application*"
    OR Processes.process="*wevtutil*cl*Security*")
by Processes.dest Processes.user Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=80
| where risk_score >= 50
| table firstTime lastTime dest user process_name process risk_score
```

## 6. Executive Summary

**The Gentlemen** is a rapidly scaling RaaS operation (tracked by Microsoft as Storm-2697) that emerged in mid-2025 and has claimed at least 478 confirmed victims across 66 countries and 20+ industry sectors. Its Go-based encryptor is notable for a built-in wormable spreading capability triggered by a `--spread` command-line flag, which deploys eight parallel lateral movement techniques (PsExec, WMIC, WinRM, scheduled tasks, service creation, SMB shares) against every reachable host on the network simultaneously.

The encryptor uses per-file Curve25519 ECDH key exchange with XChaCha20 encryption and appends the `.umc16h` extension. Pre-encryption, the malware aggressively disables Defender, clears event logs, and terminates 30+ processes and 40+ services (MSSQL, Exchange, Veeam, EDR agents). The primary initial access vector is CVE-2024-55591, a FortiOS authentication bypass, with the operators maintaining an inventory of approximately 14,700 pre-compromised FortiGate devices.

A May 2026 internal leak exposed the group's operator roster (Russian-speaking administrator "zeta88"), toolchain, G-BOT custom C2 framework, and SystemBC proxy infrastructure. Despite the leak, the group remains active. Organizations should prioritize patching CVE-2024-55591, monitoring for Gentlemen-specific scheduled task names, and detecting mass PsExec admin share activity.

**References:**
- [Microsoft Security Blog — The Gentlemen ransomware: Dissecting a self-propagating Go encryptor (May 28, 2026)](https://www.microsoft.com/en-us/security/blog/2026/05/28/the-gentlemen-ransomware-dissecting-a-self-propagating-go-encryptor/)
- [The Hacker News — The Gentlemen Ransomware Claims 478 Victims, Can Spread Like a Worm (June 11, 2026)](https://thehackernews.com/2026/06/the-gentlemen-ransomware-claims-478.html)
- [Check Point DFIR Report — The Gentlemen & SystemBC: A Sneak Peek Behind the Proxy](https://research.checkpoint.com/2026/dfir-report-the-gentlemen/)
- [MITRE ATT&CK — Data Encrypted for Impact (T1486)](https://attack.mitre.org/techniques/T1486/)
- [CVE-2024-55591 — Fortinet FortiOS Authentication Bypass](https://www.cve.org/CVERecord?id=CVE-2024-55591)
