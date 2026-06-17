# GhostTree: Recursive NTFS Junction EDR Scanner Bypass

## Description

Detects the GhostTree technique disclosed by Varonis Threat Labs (June 2026), in which an attacker creates a recursive NTFS directory junction — a junction pointing back to one of its ancestor directories — to create an infinite directory loop. When antivirus or EDR file system scanners recursively walk the directory tree, they follow the junction loop indefinitely, consuming resources and never completing the scan. Malicious payloads placed in the parent directory alongside the junction are left completely unscanned and undetected.

The technique requires only standard user write permissions (`mklink /J` via `cmd.exe` or `New-Item -ItemType Junction` via PowerShell). No administrative privileges or kernel vulnerabilities are exploited.

**Primary detection surface:** Command-line processes (`cmd.exe`, `powershell.exe`) creating NTFS junctions in user-writable directories (TEMP, AppData, ProgramData, Public). The most suspicious pattern is junction creation in staging directories commonly used by malware.

**False positive sources:** Legitimate software occasionally creates NTFS junctions during installation (e.g., Visual Studio, some games, developer tools). Filter by directory path and correlate with process parent chain to reduce noise. Junction creation in `C:\Program Files\` or `C:\Windows\` by signed installers is generally benign.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Tactic ID | TA0005 |
| Technique | Impair Defenses: Disable or Modify Tools |
| Technique ID | T1562.001 |
| Secondary Technique | Hide Artifacts: NTFS File Attributes |
| Secondary Technique ID | T1564.004 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation / Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name="cmd.exe" OR Processes.process_name="powershell.exe")
    AND ((Processes.process="*mklink*" AND Processes.process="*/J*")
         OR (Processes.process="*New-Item*" AND Processes.process="*Junction*"))
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "(?i)(\\\\temp\\\\|\\\\tmp\\\\|appdata\\\\local\\\\temp|\\\\programdata\\\\|\\\\public\\\\)"), 85,
    match(process, "(?i)(\\\\windows\\\\temp|\\\\users\\\\)"), 75,
    match(parent_process_name, "(?i)(wscript|cscript|mshta|regsvr32|rundll32|certutil)"), 90,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name="cmd.exe"
    AND Processes.process="*mklink*" AND Processes.process="*/J*"
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| rex field=process "mklink\s+/J\s+(?<junction_target>\S+)\s+(?<junction_source>\S+)"
| eval recursive_indicator=if(like(junction_target, concat("%", junction_source, "%"))
                               OR like(junction_source, concat("%", junction_target, "%")), "yes", "unknown")
| eval risk_score=case(
    recursive_indicator="yes", 95,
    match(junction_target, "(?i)(temp|tmp|appdata|public|programdata)"), 80,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user parent_process_name process junction_target junction_source recursive_indicator risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Junction source and target appear to be recursive (ancestor/descendant relationship) | 95 | Directly indicates the GhostTree recursive loop pattern |
| mklink /J targeting staging paths (TEMP, AppData, ProgramData, Public) | 85 | Staging paths are primary malware deployment locations; junction here is anomalous |
| mklink /J from script interpreter parent (wscript, mshta, cscript, rundll32) | 90 | Scripting engine spawning junction creation is a strong indicator of malware-driven evasion |
| Generic mklink /J in user-space paths | 65 | Suspicious but may have legitimate installer context; needs analyst review |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Generic post-exploitation technique (no specific actor attribution at time of disclosure) | [Varonis — GhostTree (2026-06-16)](https://www.varonis.com/blog/ghosttree-ntfs-trick) |
| DragonForce Ransomware Group | [Symantec — Backdoor.Turn (2026-06-16)](https://www.security.com/threat-intelligence/dragonforce-msteams-backdoor) — NOTE: DragonForce was disclosed the same day using process injection + legitimate-binary C2 to evade scanning; evasion techniques of this class are expected to be combined |

## References

- [Varonis Threat Labs — GhostTree: NTFS Path Manipulation Techniques (2026-06-16)](https://www.varonis.com/blog/ghosttree-ntfs-trick)
- [BleepingComputer — GhostTree Abused Recursive Windows Junctions (2026-06-16)](https://www.bleepingcomputer.com/news/security/ghosttree-attack-abused-recursive-windows-junctions-to-hide-malware/)
- [MITRE ATT&CK — T1562.001: Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
- [MITRE ATT&CK — T1564.004: Hide Artifacts: NTFS File Attributes](https://attack.mitre.org/techniques/T1564/004/)
