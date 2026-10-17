# Windows Shell Mark-of-the-Web Zone.Identifier Bypass

## Description

Detects attempts to remove or manipulate the Mark-of-the-Web (MotW) Zone.Identifier alternate data stream from files. MotW is a Windows security feature that tags files downloaded from the internet (Zone 3) or intranet so that SmartScreen, Office Protected View, and other trust controls can enforce additional scrutiny on execution.

Adversaries bypass MotW to silently remove the zone tag from a malicious file, causing downstream security controls (SmartScreen, Protected View, AppLocker path rules that check origin) to treat the file as locally trusted. Two primary methods:

1. **`Unblock-File` PowerShell cmdlet** — explicitly designed to remove MotW; legitimate admin use but also abused by malware droppers and post-exploitation frameworks
2. **Zone.Identifier ADS write/delete via cmd, streams tools, or exploit** — overwrite or delete the `file.ext:Zone.Identifier` ADS, setting ZoneId=0 (local) or removing the ADS entirely

CVE-2026-96951 (actively exploited, CISA KEV 2026-10-16) demonstrates that Windows Shell can be coerced into stripping MotW via a crafted file — the third such zero-day of 2026 (after CVE-2026-21510 and CVE-2026-32202).

**False positives:** Legitimate software distributors and IT admins occasionally use `Unblock-File` to unblock downloaded MSIs or scripts in bulk deployment pipelines. Tune by excluding trusted parent process paths (SCCM, software deployment systems). Zone.Identifier deletion events from `%ProgramFiles%` and `%WinDir%` paths are generally benign.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Tactic ID | TA0005 |
| Technique | Subvert Trust Controls: Mark-of-the-Web Bypass |
| Technique ID | T1553.005 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |

## Splunk Detection Query

**Search 1 — PowerShell Unblock-File and Zone.Identifier Manipulation**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where (Processes.process="*Unblock-File*" OR Processes.process="*Zone.Identifier*")
  AND Processes.process_name IN ("powershell.exe", "pwsh.exe")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "(?i)Unblock-File"), 75,
    match(process, "(?i)Zone\.Identifier"), 65,
    1=1, 50)
| where risk_score >= 65
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

**Search 2 — Zone.Identifier ADS Deletion from Download/Temp Paths**

Requires Sysmon event ID 26 (FileDeleteDetected) or equivalent EDR telemetry mapped to `Endpoint.Filesystem`.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_path="*Zone.Identifier*"
  AND (Filesystem.action="deleted" OR Filesystem.action="modified")
by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_id
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_path, "(?i)(\\\\Downloads\\\\|\\\\Temp\\\\|\\\\AppData\\\\Local\\\\Temp)"), 80,
    match(file_path, "(?i)\\\\Desktop\\\\"), 70,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime dest user file_path file_name process_id risk_score
```

## Risk Score Logic

**Search 1:**

| Condition | Score | Rationale |
|-----------|-------|-----------|
| `Unblock-File` cmdlet | 75 | Direct MOTW removal; legitimate bulk use exists but deserves investigation |
| `Zone.Identifier` in PowerShell args | 65 | Explicit ADS manipulation; unusual outside of pentest frameworks |

**Search 2:**

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Zone.Identifier deleted from Downloads/Temp/AppData | 80 | High-risk: stripping MOTW from internet-origin files in staging paths |
| Zone.Identifier deleted from Desktop | 70 | Elevated risk: user-desktop files commonly used as execution staging |
| Zone.Identifier deleted from other paths | 60 | Requires analyst review; may be legitimate install scripts |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Water Hydra | [MITRE ATT&CK — Water Hydra](https://attack.mitre.org/groups/G1039/) — exploited CVE-2024-21412 (prior MotW zero-day) to deliver DarkGate |
| Void Banshee | [Trend Micro — Void Banshee CVE-2024-38213](https://www.trendmicro.com/en_us/research/24/i/void-banshee-exploits-cve-2024-38213.html) — used MotW bypass to chain IE11 zero-day for Lumma Stealer delivery |
| Unknown (CVE-2026-96951) | No attribution as of 2026-10-17; CISA KEV confirms active exploitation |

## References

- [CISA KEV — CVE-2026-96951 Windows Shell MotW Bypass](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Microsoft MSRC — October 2026 Security Updates](https://msrc.microsoft.com/update-guide/releaseNote/2026-Oct)
- [SOCPrime — CVE-2026-96951 Analysis](https://socprime.com/blog/cve-2026-96951-analysis/)
- [SecurityWeek — Microsoft Patches Record 1,413 Vulnerabilities Including Exploited Windows Zero-Day](https://www.securityweek.com/microsoft-patches-record-1413-vulnerabilities-including-exploited-windows-zero-day/)
- [MITRE ATT&CK — T1553.005 Mark-of-the-Web Bypass](https://attack.mitre.org/techniques/T1553/005/)
- [Microsoft Docs — Zone.Identifier ADS and MotW](https://learn.microsoft.com/en-us/deployoffice/security/internet-macros-blocked)
