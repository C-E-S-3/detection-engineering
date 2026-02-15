# Gootloader Scheduled Task Persistence

## Description

Gootloader establishes persistence by creating scheduled tasks that re-execute the malicious JavaScript or PowerShell payload. Tasks are commonly created via `schtasks.exe` and may reference wscript, cscript, PowerShell, or .js files with obfuscated arguments. This ensures the malware survives reboots and continues execution.

False positive sources: Legitimate scheduled tasks created by IT administration. Tuning: correlate with wscript parent process for higher specificity.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Persistence |
| Tactic ID | TA0003 |
| Technique | Scheduled Task/Job: Scheduled Task |
| Technique ID | T1053.005 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where (Processes.process_name="schtasks.exe" AND Processes.process="*/create*"
    AND (Processes.process IN ("*wscript*", "*cscript*", "*powershell*", "*pwsh*", "*.js*")))
by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process
   Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "(?i)wscript.*\\.js"), 90,
    match(process, "(?i)cscript.*\\.js"), 90,
    match(process, "(?i)powershell.*-enc"), 85,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Scheduled task with wscript + .js | 90 | Classic Gootloader persistence mechanism |
| Scheduled task with cscript + .js | 90 | Variant Gootloader persistence |
| Scheduled task with encoded PowerShell | 85 | Encoded PowerShell persistence is suspicious |
| Other script interpreter references | 65 | Generic suspicious scheduled task |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Gootloader / UNC2565 | [MITRE - Gootloader (S1138)](https://attack.mitre.org/software/S1138/) |

## References

- [Mandiant - Tracking and Disrupting GootLoader Operations](https://www.mandiant.com/resources/tracking-and-disrupting-gootloader-operations)
- [MITRE ATT&CK - Scheduled Task (T1053.005)](https://attack.mitre.org/techniques/T1053/005/)
