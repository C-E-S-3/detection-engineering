# Detection Name

## Description

<!-- What behavior does this detect? Why is it suspicious or malicious? What are common false positive sources? -->

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | (e.g., Execution) |
| Tactic ID | (e.g., TA0002) |
| Technique | (e.g., Command and Scripting Interpreter: PowerShell) |
| Technique ID | (e.g., T1059.001) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| (e.g., Exploitation) |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="CHANGEME"
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    1=1, 50)
| where risk_score >= 50
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| (describe condition) | (score) | (why this score) |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| (e.g., Lazarus Group) | [MITRE ATT&CK](https://attack.mitre.org/groups/G0032/) |

## References

- [Link to threat intel or technique documentation]
