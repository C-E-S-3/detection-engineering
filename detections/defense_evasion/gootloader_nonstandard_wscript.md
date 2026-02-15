# Gootloader Cscript/Wscript Executing from Non-Standard Directories

## Description

Gootloader may stage its JavaScript payload in non-standard directories. This detection identifies `cscript.exe` or `wscript.exe` executing `.js` files from paths outside `C:\Windows\System32`, `C:\Windows\SysWOW64`, and `C:\Program Files`. Script interpreter execution from user-writable directories is suspicious and warrants investigation.

False positive sources: Legitimate admin scripts stored in user directories. Tuning: whitelist specific known script paths.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Tactic ID | TA0005 |
| Technique | System Binary Proxy Execution |
| Technique ID | T1218 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name IN ("wscript.exe", "cscript.exe")
    AND NOT Processes.process IN ("*\\Windows\\System32\\*", "*\\Windows\\SysWOW64\\*", "*\\Program Files*")
    AND Processes.process="*.js*"
by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "(?i)\\\\Users\\\\.*\\\\AppData\\\\"), 80,
    match(process, "(?i)\\\\Users\\\\.*\\\\Downloads\\\\"), 80,
    match(process, "(?i)\\\\Temp\\\\"), 85,
    match(process, "(?i)\\\\ProgramData\\\\"), 75,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| JS execution from Temp directories | 85 | High-risk staging path |
| JS execution from AppData or Downloads | 80 | Common Gootloader delivery paths |
| JS execution from ProgramData | 75 | Writable by all users, used for staging |
| Other non-standard paths | 65 | Anomalous script execution location |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Gootloader / UNC2565 | [MITRE - Gootloader (S1138)](https://attack.mitre.org/software/S1138/) |

## References

- [Mandiant - Tracking and Disrupting GootLoader Operations](https://www.mandiant.com/resources/tracking-and-disrupting-gootloader-operations)
