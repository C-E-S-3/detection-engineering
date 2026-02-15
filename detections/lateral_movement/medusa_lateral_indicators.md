# Medusa Lateral Movement Indicators

## Description

Detects Medusa-specific lateral movement patterns: PowerShell tools (Invoke-SMBExec, Invoke-WMIExec, Invoke-TheHash), admin share access (`\\admin$`, `\\c$`), and credential dumping via rundll32 with comsvcs.dll MiniDump. Correlates across destinations to identify spreading behavior (activity targeting 3+ unique hosts).

False positive sources: Legitimate admin share access by IT staff, authorized credential collection tools. Tuning: adjust the unique_targets threshold.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Lateral Movement |
| Tactic ID | TA0008 |
| Technique | Remote Services: SMB/Windows Admin Shares |
| Technique ID | T1021.002 |
| Secondary Techniques | OS Credential Dumping (T1003.001), System Binary Proxy Execution: Rundll32 (T1218.011) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where (
    (Processes.process_name IN ("powershell.exe", "pwsh.exe")
     AND Processes.process IN ("*Invoke-SMBExec*", "*Invoke-WMIExec*", "*Invoke-TheHash*"))
    OR
    (Processes.process IN ("*\\admin$*", "*\\c$*")
     AND Processes.process_name IN ("powershell.exe", "cmd.exe"))
    OR
    (Processes.process_name="rundll32.exe"
     AND Processes.process IN ("*comsvcs.dll*", "*MiniDump*"))
)
by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
   Processes.process Processes.process_id Processes.original_file_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eventstats dc(dest) as unique_targets by user
| where unique_targets >= 3
| table firstTime lastTime user dest parent_process_name process_name process unique_targets
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Offensive tool usage + 3+ target hosts | Critical | Active lateral movement campaign with spreading behavior |
| Admin share access from script host + 3+ targets | High | Automated admin share enumeration/access |
| comsvcs.dll MiniDump + 3+ targets | Critical | Credential harvesting across multiple systems |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Medusa Ransomware | [MITRE - Medusa (S1131)](https://attack.mitre.org/software/S1131/), [CISA - StopRansomware: Medusa](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a) |

## References

- [CISA - StopRansomware: Medusa](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a)
- [MITRE ATT&CK - SMB/Windows Admin Shares (T1021.002)](https://attack.mitre.org/techniques/T1021/002/)
