# WMI Command Execution Risk Rule

## Description

Detects execution of `wmic.exe` or `scrcons.exe` (WMI Script Consumer) and applies risk scoring based on the specific WMI commands being executed. WMI is frequently abused by adversaries for process creation, discovery, lateral movement, and defense evasion (shadow copy deletion).

False positive sources: Legitimate administrative WMI usage for system management and inventory. Tuning: filter known management tool parent processes.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Execution |
| Tactic ID | TA0002 |
| Technique | Windows Management Instrumentation |
| Technique ID | T1047 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
| tstats summariesonly=false count,
  values(Processes.process) as process,
  values(Processes.parent_process_name) as parent_process,
  values(Processes.user) as user,
  min(_time) as firstTime,
  max(_time) as lastTime
  FROM datamodel=Endpoint.Processes
  WHERE (Processes.process_name IN ("wmic.exe", "scrcons.exe")
    OR Processes.original_file_name IN ("wmic.exe", "scrcons.exe"))
  BY Processes.dest, Processes.process_name, Processes.process_guid
| `drop_dm_object_name("Processes")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    like(process, "%process call create%"), 50,
    like(process, "%/node:%") OR like(process, "%/NODE:%"), 45,
    like(process, "%shadowcopy%"), 40,
    like(process, "%AntiVirusProduct%") OR like(process, "%AntiSpywareProduct%"), 35,
    like(process, "%namespace%"), 30,
    1==1, 25
  )
| eval risk_message="WMI command execution detected on dest=".dest." process=".process_name." user=".user
| eval risk_object=dest
| eval risk_object_type="system"
| eval threat_object=user
| eval threat_object_type="user"
| fields firstTime, lastTime, dest, user, process_name, process, parent_process, count, risk_score, risk_object, risk_object_type, threat_object, threat_object_type, risk_message
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| process call create | 50 | Remote/local process creation via WMI - common lateral movement technique |
| /node: remote execution | 45 | Targeting remote systems via WMI |
| shadowcopy operations | 40 | Shadow copy deletion is a ransomware pre-encryption step |
| AV product enumeration | 35 | Defense evasion reconnaissance |
| namespace queries | 30 | WMI namespace enumeration for discovery |
| Other WMI activity | 25 | Baseline WMI usage |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Medusa Ransomware | [CISA - StopRansomware: Medusa](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a) |
| Lazarus Group (HIDDEN COBRA) | [MITRE - Lazarus Group (G0032)](https://attack.mitre.org/groups/G0032/) |

## References

- [MITRE ATT&CK - Windows Management Instrumentation (T1047)](https://attack.mitre.org/techniques/T1047/)
