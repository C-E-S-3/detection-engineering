# Medusa SMB/WMI Lateral Execution

## Description

Detects Medusa ransomware lateral movement techniques using PowerShell-based `Invoke-SMBExec` and `Invoke-WMIExec` tools. Also covers WMI remote process creation via `wmic.exe process call create` when spawned from PowerShell or cmd.exe. These are primary lateral movement tools used by Medusa operators to spread across the network.

False positive sources: Red team exercises using similar tools. Tuning: correlate with authorized penetration testing windows.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Lateral Movement |
| Tactic ID | TA0008 |
| Technique | Remote Services: SMB/Windows Admin Shares |
| Technique ID | T1021.002 |
| Secondary Technique | Windows Management Instrumentation (T1047) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where (Processes.process_name IN ("powershell.exe", "pwsh.exe", "powershell_ise.exe")
    AND Processes.process IN ("*Invoke-SMBExec*", "*Invoke-WMIExec*"))
    OR (Processes.process_name IN ("wmiprvse.exe", "wmic.exe")
    AND Processes.parent_process_name IN ("powershell.exe", "pwsh.exe", "cmd.exe")
    AND Processes.process IN ("*process call create*", "*wmic*process*"))
by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process
   Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "(?i)Invoke-SMBExec"), 85,
    match(process, "(?i)Invoke-WMIExec"), 85,
    match(process, "(?i)process call create") AND match(parent_process_name, "(?i)powershell"), 75,
    1=1, 50)
| where risk_score >= 75
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Invoke-SMBExec detected | 85 | Known offensive tool for pass-the-hash SMB lateral movement |
| Invoke-WMIExec detected | 85 | Known offensive tool for pass-the-hash WMI lateral movement |
| WMI process creation from PowerShell | 75 | Suspicious remote execution pattern |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Medusa Ransomware | [MITRE - Medusa (S1131)](https://attack.mitre.org/software/S1131/), [CISA - StopRansomware: Medusa](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a) |

## References

- [CISA - StopRansomware: Medusa](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a)
- [MITRE ATT&CK - SMB/Windows Admin Shares (T1021.002)](https://attack.mitre.org/techniques/T1021/002/)
