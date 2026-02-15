# Gootloader Wscript Spawning PowerShell - Stage Transition

## Description

A key indicator of Gootloader execution is the process chain where `wscript.exe` (executing the initial .js file) spawns `powershell.exe` or `cscript.exe` for the next stage. This parent-child relationship is uncommon in legitimate activity and is a strong signal for Gootloader stage transition from JavaScript to PowerShell-based fileless execution.

False positive sources: Very rare. Some legacy enterprise scripts may chain wscript to PowerShell.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Execution |
| Tactic ID | TA0002 |
| Technique | Command and Scripting Interpreter: PowerShell |
| Technique ID | T1059.001 |
| Secondary Technique | Command and Scripting Interpreter: JavaScript (T1059.007) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name="wscript.exe"
    AND Processes.process_name IN ("powershell.exe", "pwsh.exe", "cscript.exe", "cmd.exe")
by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process
   Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name="powershell.exe" OR process_name="pwsh.exe", 90,
    process_name="cscript.exe", 80,
    process_name="cmd.exe", 70,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime dest user parent_process_name parent_process process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Wscript spawning PowerShell/pwsh | 90 | High-confidence Gootloader stage transition; rarely legitimate |
| Wscript spawning cscript | 80 | Known Gootloader variant behavior |
| Wscript spawning cmd.exe | 70 | Less specific but still suspicious from wscript parent |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Gootloader / UNC2565 | [MITRE - Gootloader (S1138)](https://attack.mitre.org/software/S1138/) |

## References

- [Mandiant - Tracking and Disrupting GootLoader Operations](https://www.mandiant.com/resources/tracking-and-disrupting-gootloader-operations)
