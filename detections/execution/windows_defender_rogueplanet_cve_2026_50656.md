# RoguePlanet Windows Defender Privilege Escalation (CVE-2026-50656)

## Description

Detects exploitation of CVE-2026-50656 (RoguePlanet), an unpatched zero-day race condition in the Windows Defender Malware Protection Engine (`MsMpEng.exe`). Disclosed June 10, 2026 by security researcher "Nightmare Eclipse," the exploit races a symlink swap against Defender's scan to cause the malware engine to execute an attacker-controlled payload at SYSTEM privilege level, resulting in a `cmd.exe` shell as NT AUTHORITY\SYSTEM.

The vulnerability is classified CVSS 7.8 (HIGH) and Microsoft's MSRC rates it "Exploitation More Likely." No patch is available as of 2026-06-19. The public PoC is available on GitHub and works on fully patched Windows 10 and Windows 11 systems.

**Detection approach:** MsMpEng.exe (Windows Defender's malware protection engine process) has a tightly bounded set of legitimate child processes: `MpCmdRun.exe`, `MpSigStub.exe`, `MpDlpCmd.exe`. Any shell interpreter (`cmd.exe`, `powershell.exe`, `pwsh.exe`) spawned as a direct child of MsMpEng.exe is a high-confidence exploitation indicator. An additional rule detects SYSTEM-integrity level processes from this parent, confirming successful exploitation.

**False positive sources:** Defender Endpoint Protection scripts may occasionally spawn MpCmdRun.exe which in turn spawns PowerShell for scan remediation — these are excluded. Direct MsMpEng.exe → shell spawning with no MpCmdRun.exe intermediary has no known benign explanation.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Privilege Escalation (TA0004) — placed in `execution/` per repo structure |
| Tactic ID | TA0004 |
| Technique | Exploitation for Privilege Escalation |
| Technique ID | T1068 |
| Secondary Technique | Abuse Elevation Control Mechanism |
| Secondary Technique ID | T1548 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
| comment "Query 1: MsMpEng.exe spawning shell interpreter — primary RoguePlanet indicator"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name="MsMpEng.exe"
    AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","conhost.exe","wsl.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    user="NT AUTHORITY\\SYSTEM", 98,
    process_name IN ("cmd.exe","powershell.exe","pwsh.exe"), 90,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

```spl
| comment "Query 2: MsMpEng.exe spawning any unexpected non-Defender binary"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name="MsMpEng.exe"
    AND NOT Processes.process_name IN ("MpCmdRun.exe","MpSigStub.exe","MpDlpCmd.exe","MpUXSrv.exe","NisSrv.exe","ConfigSecurityPolicy.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    user="NT AUTHORITY\\SYSTEM", 96,
    1=1, 80)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

```spl
| comment "Query 3: Executable dropped to Defender scan directory (pre-exploitation staging)"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path LIKE "%ProgramData\\Microsoft\\Windows Defender\\Scans%"
    AND Filesystem.file_name LIKE "%.exe" OR Filesystem.file_name LIKE "%.dll"
    OR Filesystem.file_name LIKE "%.ps1" OR Filesystem.file_name LIKE "%.bat"
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    file_name LIKE "%.exe", 80,
    file_name LIKE "%.dll", 78,
    file_name LIKE "%.ps1", 75,
    1=1, 60)
| where risk_score >= 75
| table firstTime lastTime dest user file_path file_name risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| MsMpEng.exe → cmd.exe/powershell.exe as SYSTEM | 98 | Near-certain confirmed CVE-2026-50656 exploitation; SYSTEM shell from Defender has no benign explanation |
| MsMpEng.exe → any shell interpreter (non-SYSTEM) | 90 | Highly suspicious; RoguePlanet race condition may not always deliver SYSTEM on first spawn |
| MsMpEng.exe → any unexpected non-Defender process | 80 | Anomalous Defender behavior; investigate process ancestry |
| Executable dropped to Defender scan directory | 75 | Pre-exploitation staging; attacker plants bait file for Defender to scan |
| Symlink/junction targeting Defender scan paths | 78 | Core RoguePlanet mechanism (symlink swap during Defender scan) |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| "Nightmare Eclipse" (researcher, PoC author) | [Bleeping Computer — RoguePlanet zero-day (2026-06-17)](https://www.bleepingcomputer.com/news/microsoft/microsoft-working-on-defender-patch-for-rogueplanet-zero-day/) |
| Any financially motivated actor with local access | Microsoft MSRC assessment: "Exploitation More Likely" |

## References

- [Help Net Security — Microsoft working on patch for RoguePlanet (2026-06-17)](https://www.helpnetsecurity.com/2026/06/17/rogueplanet-zero-day-cve-2026-50656/)
- [SecurityWeek — Microsoft Working on Patch for RoguePlanet Zero-Day (2026-06-17)](https://www.securityweek.com/microsoft-working-on-patch-for-rogueplanet-zero-day/)
- [The Hacker News — Microsoft Confirms RoguePlanet Defender Zero-Day (2026-06-17)](https://thehackernews.com/2026/06/microsoft-confirms-rogueplanet-defender_02022423645.html)
- [Morphisec Blog — RoguePlanet: When Your Detector Becomes the Attack Surface](https://www.morphisec.com/blog/microsoft-defender-zero-day-rogueplanet-when-your-detector-becomes-the-attack-surface/)
- [Tenable — CVE-2026-50656](https://www.tenable.com/cve/CVE-2026-50656)
- [MITRE ATT&CK — T1068 Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
- [Wazuh rules — `wazuh/rules/windows_cve_2026_50656_rogueplanet.xml` (rules 102810-102815)](../../wazuh/rules/windows_cve_2026_50656_rogueplanet.xml)
