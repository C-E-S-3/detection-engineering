# Gootloader Full Kill Chain Process Correlation

## Description

This detection correlates the full Gootloader process chain: `wscript.exe` executing a `.js` file which then spawns PowerShell within a 2-minute window on the same host. Observing this full chain is a high-confidence indicator of Gootloader activity and should be treated as critical.

False positive sources: Extremely rare. This specific chain (wscript + .js + PowerShell child) has almost no legitimate use case.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Execution |
| Tactic ID | TA0002 |
| Technique | Command and Scripting Interpreter: JavaScript |
| Technique ID | T1059.007 |
| Secondary Technique | Command and Scripting Interpreter: PowerShell (T1059.001) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="wscript.exe"
    AND Processes.process="*.js*"
by Processes.dest Processes.user Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| rename process_id as wscript_pid
| join dest
    [| tstats `security_content_summariesonly` count min(_time) as ps_firstTime max(_time) as ps_lastTime
     from datamodel=Endpoint.Processes
     where Processes.parent_process_name="wscript.exe"
         AND Processes.process_name IN ("powershell.exe", "pwsh.exe")
     by Processes.dest Processes.user Processes.parent_process_name
        Processes.process_name Processes.process Processes.parent_process_id
     | `drop_dm_object_name(Processes)`
     | rename process_name as child_process_name process as child_process parent_process_id as wscript_pid]
| where ps_firstTime >= firstTime AND (ps_firstTime - firstTime) < 120
| eval risk_score=95
| eval risk_level="critical"
| table firstTime ps_firstTime dest user process_name process child_process_name child_process risk_score risk_level
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Full wscript(.js) -> PowerShell chain within 2 min | 95 (Critical) | Near-certain Gootloader execution; this chain is almost never legitimate |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Gootloader / UNC2565 | [MITRE - Gootloader (S1138)](https://attack.mitre.org/software/S1138/) |

## References

- [Mandiant - Tracking and Disrupting GootLoader Operations](https://www.mandiant.com/resources/tracking-and-disrupting-gootloader-operations)
