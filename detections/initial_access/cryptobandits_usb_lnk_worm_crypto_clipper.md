# CryptoBandits: USB LNK Worm Executing Crypto Clipboard Hijacker via WScript

## Description

Detects execution of the CryptoBandits clipboard-hijacking worm delivered via malicious LNK shortcut files on USB drives. The worm replaces legitimate document files (.doc, .xlsx, .pdf) with LNK shortcuts bearing the same names; when a victim opens a file, `explorer.exe` launches `wscript.exe` or `cscript.exe` to execute an encrypted JavaScript payload from a 5-character staging directory under `C:\Users\Public\Documents\`. The malware also deploys a bundled Tor proxy (`ugate.exe`) for covert C2, creates scheduled tasks via scripting engines for persistence, and adds Defender exclusions for its staging folder.

False positive sources: legitimate scripts invoked from shared/public document paths (uncommon but possible in some enterprise script automation configurations). The `ugate.exe` process name is highly anomalous in corporate environments.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Replication Through Removable Media |
| Technique ID | T1091 |
| Secondary Tactic | Execution |
| Secondary Technique | Command and Scripting Interpreter: JavaScript |
| Secondary ID | T1059.007 |
| Tertiary Tactic | Persistence |
| Tertiary Technique | Scheduled Task/Job: Scheduled Task |
| Tertiary ID | T1053.005 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Exploitation |
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where (Processes.process_name IN ("wscript.exe","cscript.exe")
    AND Processes.parent_process_name="explorer.exe"
    AND match(Processes.process, "(?i)Users\\\\Public\\\\Documents"))
   OR Processes.process_name="ugate.exe"
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name="ugate.exe", 95,
    match(process,"(?i)Users\\\\Public\\\\Documents\\\\[a-z]{5}"), 85,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="schtasks.exe"
    AND Processes.parent_process_name IN ("wscript.exe","cscript.exe","powershell.exe","cmd.exe")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| where risk_score >= 85
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="powershell.exe"
    AND match(Processes.process,"(?i)Add-MpPreference")
    AND match(Processes.process,"(?i)(ExclusionPath|ExclusionProcess)")
    AND match(Processes.process,"(?i)Users\\\\Public\\\\Documents")
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
| `ugate.exe` process detected | 95 | CryptoBandits-specific Tor proxy binary name; near-zero legitimate use in corporate environments |
| WScript/CScript launched from Explorer with Public\Documents\[5-char] path | 85 | Highly anomalous script execution pattern matching known CryptoBandits staging path |
| schtasks.exe child of scripting engine | 85 | Persistence mechanism; scripting engines spawning task scheduler is suspicious |
| PowerShell adding Defender exclusion for Public\Documents | 90 | Direct defense evasion matching CryptoBandits staging folder protection behavior |
| WScript/CScript from Explorer in Public\Documents (generic) | 75 | Suspicious but lower confidence without staging path match |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| CryptoBandits (unattributed, financially motivated) | [Microsoft Security Blog — CryptoBandits (2026-06-17)](https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/) |

## References

- [Microsoft Security Blog — CryptoBandits (2026-06-17)](https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/)
- [BleepingComputer — USB worm spreads crypto-stealing malware (2026-06-21)](https://www.bleepingcomputer.com/news/security/usb-worm-spreads-crypto-stealing-malware-via-windows-shortcut-files/)
- [MITRE ATT&CK — T1091: Replication Through Removable Media](https://attack.mitre.org/techniques/T1091/)
- [MITRE ATT&CK — T1115: Clipboard Data](https://attack.mitre.org/techniques/T1115/)
- [MITRE ATT&CK — T1053.005: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
