# Gootloader Wscript Executing JavaScript from User Directories

## Description

Gootloader delivers malicious `.js` files inside ZIP archives downloaded from SEO-poisoned search results. Victims double-click the JavaScript file, which launches `wscript.exe`. This detection identifies `wscript.exe` executing `.js` files from common download and staging paths (Downloads, Temp, AppData, Desktop).

False positive sources: Legitimate administrative scripts using wscript.exe. Tuning: whitelist known signed scripts by hash or path.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Execution |
| Tactic ID | TA0002 |
| Technique | Command and Scripting Interpreter: JavaScript |
| Technique ID | T1059.007 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="wscript.exe"
    AND (Processes.process IN ("*\\Downloads\\*.js*", "*\\Temp\\*.js*", "*\\AppData\\Local\\*.js*", "*\\Desktop\\*.js*"))
by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process
   Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "(?i)\\\\Downloads\\\\.*\\.js"), 80,
    match(process, "(?i)\\\\Temp\\\\.*\\.js"), 85,
    match(process, "(?i)\\\\Desktop\\\\.*\\.js"), 75,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| JS execution from Temp directory | 85 | Temp is a high-risk staging path for malware |
| JS execution from Downloads directory | 80 | Primary Gootloader delivery path |
| JS execution from Desktop | 75 | Common user extraction path |
| JS execution from other user paths | 60 | Anomalous but lower confidence |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Gootloader / UNC2565 | [MITRE - Gootloader (S1138)](https://attack.mitre.org/software/S1138/) |

## References

- [Mandiant - Tracking and Disrupting GootLoader Operations](https://www.mandiant.com/resources/tracking-and-disrupting-gootloader-operations)
- [HP Wolf Security - Gootloader Deep-Dive Analysis](https://threatresearch.ext.hp.com/gootloader-inside-out/)
