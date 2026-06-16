# Gentlemen Ransomware: Wormable PsExec Spreading and Artifact Detection

## Description

Detects the Storm-2697 "Gentlemen" ransomware group's signature behaviors: creation of campaign-specific scheduled tasks used for persistence and worm-stage lateral movement, appearance of encrypted files bearing the `.umc16h` extension, the `README-GENTLEMEN.txt` ransom note, and the `gentlemen.bmp` wallpaper artifact. Also detects the mass PsExec lateral movement pattern used when the `--spread` flag is active, where the encryptor copies itself to `C$\Temp\` on 5+ remote hosts in parallel.

False positive sources: Near-zero for the scheduled task name and file artifact searches (names and extension are highly specific to this malware family). The PsExec admin share detection may fire on legitimate large-scale software distribution tooling; correlation with the ransomware artifact searches increases confidence.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Impact |
| Tactic ID | TA0040 |
| Technique | Data Encrypted for Impact |
| Technique ID | T1486 |
| Secondary Tactic | Lateral Movement |
| Secondary Tactic ID | TA0008 |
| Secondary Technique | Lateral Tool Transfer / Remote Services: Windows Remote Management |
| Secondary Technique IDs | T1570, T1021.006 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

### Query 1 — Gentlemen-Specific Scheduled Task Creation

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

### Query 2 — Encrypted File Extension and Ransom Artifacts

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where (Filesystem.file_name="*.umc16h"
    OR Filesystem.file_name="README-GENTLEMEN.txt"
    OR Filesystem.file_name="gentlemen.bmp")
by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=99
| where risk_score >= 50
| table firstTime lastTime dest user file_name file_path risk_score
```

### Query 3 — Mass PsExec Admin Share Lateral Movement (Worm Spreading)

```spl
| tstats `security_content_summariesonly` count dc(Processes.dest) as remote_target_count
    min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where (Processes.process_name="psexec.exe" OR Processes.process_name="psexec64.exe")
  AND Processes.process="*C$*Temp*"
by Processes.src Processes.user Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| where remote_target_count >= 5
| eval risk_score=case(remote_target_count >= 20, 95, remote_target_count >= 10, 85, 1=1, 75)
| table firstTime lastTime src user process_name process remote_target_count risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| `.umc16h` file extension detected | 99 | Extension is unique to Gentlemen ransomware; indicates active encryption in progress |
| `README-GENTLEMEN.txt` or `gentlemen.bmp` detected | 99 | Campaign-specific artifacts; near-certain true positive |
| `gentlemen_system` or `UpdateGU2`/`DefSvc` scheduled task created | 99 | Task names unique to this malware; persistence stage of attack |
| PsExec admin share copy to 5–9 remote targets | 75 | Mass lateral movement; may be legitimate software deployment |
| PsExec admin share copy to 10–19 remote targets | 85 | Consistent with worm spreading; very unlikely to be legitimate |
| PsExec admin share copy to 20+ remote targets | 95 | Worm-speed propagation; near-certain ransomware spreading |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Storm-2697 / The Gentlemen | [Microsoft Security Blog (May 28, 2026)](https://www.microsoft.com/en-us/security/blog/2026/05/28/the-gentlemen-ransomware-dissecting-a-self-propagating-go-encryptor/) |
| Storm-2697 / The Gentlemen | [MITRE ATT&CK — T1486 Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/) |

## References

- [Microsoft Security Blog — The Gentlemen ransomware: Dissecting a self-propagating Go encryptor (May 28, 2026)](https://www.microsoft.com/en-us/security/blog/2026/05/28/the-gentlemen-ransomware-dissecting-a-self-propagating-go-encryptor/)
- [The Hacker News — The Gentlemen Ransomware Claims 478 Victims, Can Spread Like a Worm (June 11, 2026)](https://thehackernews.com/2026/06/the-gentlemen-ransomware-claims-478.html)
- [Check Point DFIR Report — The Gentlemen & SystemBC (May 2026)](https://research.checkpoint.com/2026/dfir-report-the-gentlemen/)
- [CVE-2024-55591 — Fortinet FortiOS Authentication Bypass (initial access vector)](https://www.cve.org/CVERecord?id=CVE-2024-55591)
- [MITRE ATT&CK — T1486 Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK — T1570 Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570/)
