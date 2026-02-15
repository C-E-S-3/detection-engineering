# Gootloader PowerShell Decoding and Executing Payload from Registry

## Description

After initial JavaScript execution, Gootloader uses PowerShell to read encoded payloads stored in the registry, decode them, and execute them in memory. This detection identifies PowerShell commands that reference registry paths (HKCU, Get-ItemProperty) in combination with decoding functions (FromBase64String, Invoke-Expression).

False positive sources: Some legitimate software installation/update scripts read encoded configuration from registry. Tuning: whitelist specific signed processes.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Execution |
| Tactic ID | TA0002 |
| Technique | Command and Scripting Interpreter: PowerShell |
| Technique ID | T1059.001 |
| Secondary Tactic | Defense Evasion (TA0005) - T1140 Deobfuscate/Decode Files or Information |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name IN ("powershell.exe", "pwsh.exe")
    AND (Processes.process IN ("*HKCU*", "*HKEY_CURRENT_USER*", "*Get-ItemProperty*", "*gp *"))
    AND (Processes.process IN ("*[System.Convert]*", "*FromBase64String*", "*[System.Text.Encoding]*",
         "*Invoke-Expression*", "*iex *", "*-encodedcommand*", "*-enc *"))
by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process
   Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "(?i)FromBase64String") AND match(process, "(?i)HKCU"), 95,
    match(process, "(?i)Invoke-Expression") AND match(process, "(?i)Get-ItemProperty"), 90,
    match(process, "(?i)-enc") AND match(process, "(?i)HKEY_CURRENT_USER"), 85,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| FromBase64String + HKCU reference | 95 | Near-certain Gootloader registry-to-memory execution |
| Invoke-Expression + Get-ItemProperty | 90 | Classic registry read-and-execute pattern |
| Encoded command + HKEY_CURRENT_USER | 85 | Encoded PowerShell reading user registry hive |
| Other registry + decode combinations | 70 | Suspicious but lower specificity |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Gootloader / UNC2565 | [MITRE - Gootloader (S1138)](https://attack.mitre.org/software/S1138/) |

## References

- [Mandiant - Tracking and Disrupting GootLoader Operations](https://www.mandiant.com/resources/tracking-and-disrupting-gootloader-operations)
