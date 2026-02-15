# Gootloader PowerShell with Long Encoded Command Line

## Description

Gootloader frequently uses PowerShell with heavily obfuscated or base64-encoded commands. This detection identifies PowerShell execution with unusually long command lines (500+ characters), which is characteristic of encoded Gootloader payloads. Additional risk factors include the presence of encoded command flags, hidden window style, and wscript as parent process.

False positive sources: Some legitimate deployment tools (SCCM, Intune) use encoded PowerShell commands. Tuning: filter by known parent processes from management tools.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Execution |
| Tactic ID | TA0002 |
| Technique | Command and Scripting Interpreter: PowerShell |
| Technique ID | T1059.001 |
| Secondary Technique | Obfuscated Files or Information (T1027) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name IN ("powershell.exe", "pwsh.exe")
by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process
   Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval cmd_length=len(process)
| eval has_encoded_cmd=if(match(process, "(?i)(-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{100,}"), 1, 0)
| eval has_hidden_window=if(match(process, "(?i)-w(indowstyle)?\s*(hidden|1)"), 1, 0)
| eval has_noprofile=if(match(process, "(?i)-nop(rofile)?"), 1, 0)
| eval risk_score=case(
    cmd_length > 2000 AND has_encoded_cmd=1, 90,
    cmd_length > 1000 AND has_encoded_cmd=1, 85,
    cmd_length > 500 AND has_hidden_window=1, 75,
    cmd_length > 2000, 70,
    1=1, 50)
| eval risk_score=if(has_hidden_window=1 AND has_noprofile=1, risk_score+10, risk_score)
| eval risk_score=if(match(parent_process_name, "(?i)wscript"), risk_score+10, risk_score)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name cmd_length has_encoded_cmd has_hidden_window risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Command > 2000 chars + encoded command flag | 90 | Very long encoded commands are characteristic of Gootloader |
| Command > 1000 chars + encoded command flag | 85 | Long encoded commands warrant investigation |
| Command > 500 chars + hidden window | 75 | Hidden window with long commands is suspicious |
| Command > 2000 chars (no encoding flag) | 70 | Very long commands alone are anomalous |
| +10 bonus: hidden window + noprofile | - | Combined evasion flags increase risk |
| +10 bonus: wscript parent process | - | Wscript parent strongly suggests Gootloader chain |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Gootloader / UNC2565 | [MITRE - Gootloader (S1138)](https://attack.mitre.org/software/S1138/) |

## References

- [Mandiant - Tracking and Disrupting GootLoader Operations](https://www.mandiant.com/resources/tracking-and-disrupting-gootloader-operations)
