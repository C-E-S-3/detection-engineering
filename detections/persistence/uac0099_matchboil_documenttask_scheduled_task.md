# UAC-0099 MATCHBOIL DocumentTask Scheduled Task Persistence

## Description

Detects creation of a Windows scheduled task named "DocumentTask," a persistence indicator specific to UAC-0099's MATCHBOIL downloader. MATCHBOIL creates this task after downloading the MATCHWOK C# backdoor to maintain persistence across reboots. The task name has been consistent across MATCHBOIL V2 and V3 variants targeting Ukrainian critical infrastructure (transportation, manufacturing, energy sectors).

False positives: Unlikely. The task name "DocumentTask" has no known legitimate use. Any occurrence should be treated as high-priority and investigated immediately.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Persistence |
| Tactic ID | TA0003 |
| Technique | Scheduled Task/Job: Scheduled Task |
| Technique ID | T1053.005 |
| Secondary Tactic | Execution |
| Secondary Technique ID | T1059.005 (VBScript delivery chain) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Installation |

## Splunk Detection Query

```spl
index=wineventlog EventCode=4698
| rex field=Message "Task Name:\s*(?<task_name>[^\r\n]+)"
| rex field=Message "(?:Task Author|Run As User|Principal):\s*(?<task_user>[^\r\n]+)"
| rex field=Message "(?:Exec|Command|Actions)[^\r\n]*\r?\n[^\r\n]*?(?:Command|Path):\s*(?<task_command>[^\r\n]+)"
| where like(lower(task_name), "%documenttask%")
| eval risk_score=90
| `security_content_ctime(_time)`
| table _time dest task_name task_user task_command risk_score
```

**Alternative — Endpoint Process datamodel hunt for schtasks spawned by script interpreters creating DocumentTask:**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.parent_process_name IN ("wscript.exe","mshta.exe","cscript.exe","powershell.exe","cmd.exe"))
    AND Processes.process_name="schtasks.exe"
    AND Processes.process="*DocumentTask*"
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Scheduled task named `DocumentTask` created (Event 4698) | 90 | Task name is a known UAC-0099 MATCHBOIL artifact with no legitimate use |
| schtasks.exe with `DocumentTask` argument spawned by script interpreter | 90 | Script interpreter spawning schtasks with this specific name is highly anomalous |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| UAC-0099 | [ESET — MATCHBOIL: New tricks, same old evil intentions (2026-10-08)](https://www.welivesecurity.com/en/eset-research/matchboil-new-tricks-same-old-evil-intentions/), [CERT-UA](https://cert.gov.ua/), [MITRE ATT&CK — T1053.005](https://attack.mitre.org/techniques/T1053/005/) |

## References

- [ESET WeLiveSecurity — MATCHBOIL: New tricks, same old evil intentions (2026-10-08)](https://www.welivesecurity.com/en/eset-research/matchboil-new-tricks-same-old-evil-intentions/)
- [The Record — Russian-aligned spies upgrade malware used in attacks on Ukrainian transport, energy firms](https://therecord.media/russia-ukraine-malware-transportation)
- [Help Net Security — What is MATCHBOIL? (2026-10-08)](https://www.helpnetsecurity.com/2026/10/08/matchboil-malware-uac-0099/)
- [MITRE ATT&CK — T1053.005 Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
