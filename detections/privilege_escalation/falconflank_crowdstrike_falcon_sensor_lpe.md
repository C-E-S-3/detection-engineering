# FalconFlank — CrowdStrike Falcon Sensor Local Privilege Escalation via Cleanup Routine Abuse

## Description

Detects exploitation of the FalconFlank local privilege escalation technique (public PoC released 2026-09-03 by researcher Chaotic Eclipse) targeting the CrowdStrike Falcon Sensor for Windows. The attack abuses the Falcon macro-remediation cleanup service (`CsFalconService.exe`), which runs as SYSTEM, by planting attacker-controlled files or symbolic links in paths processed during cleanup operations. Successful exploitation results in `CsFalconService.exe` spawning a SYSTEM-privileged child process under attacker control.

False positives are expected to be near-zero — `CsFalconService.exe` has no legitimate reason to spawn interactive shells or scripting engines. Any match should be treated as high-priority.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| **Tactic** | Privilege Escalation (TA0004) |
| **Technique** | Exploitation for Privilege Escalation (T1068) |
| **Secondary Tactic** | Defense Evasion (TA0005) |
| **Secondary Technique** | Impair Defenses: Disable or Modify Tools (T1562.001) |

## Lockheed Martin Kill Chain Phase

**Exploitation** — Post-initial-access LPE used to escalate from standard user to SYSTEM.

## Splunk SPL Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name IN ("CsFalconService.exe","csfalconservice.exe","CSFalconService.exe","CsFalconContainer.exe")
  AND Processes.process_name IN (
    "cmd.exe","powershell.exe","pwsh.exe",
    "wscript.exe","cscript.exe","mshta.exe",
    "rundll32.exe","regsvr32.exe","certutil.exe",
    "net.exe","net1.exe","whoami.exe","schtasks.exe"
  )
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
   Processes.parent_process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table dest user parent_process_name process_name process
         process_id parent_process_id risk_score firstTime lastTime
```

### Supplemental: Symbolic Link / Junction Creation Near Falcon Paths

```spl
index=* source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=17
[ search EventCode=17 TargetObject="*\\ProgramData\\CrowdStrike\\*"
  OR TargetObject="*\\Windows\\Temp\\*" ]
| eval suspicious_creator=if(NOT match(User,"SYSTEM|LOCAL SERVICE|NETWORK SERVICE"), "true", "false")
| where suspicious_creator="true"
| table _time Computer User TargetObject ProcessGuid
| sort -_time
```

## Risk Score Logic

| Score | Rationale |
|-------|-----------|
| **95 (Critical)** | Any shell or scripting engine spawned by `CsFalconService.exe` is anomalous. No benign explanation. FalconFlank PoC is publicly available as of 2026-09-03. |

## Associated Threat Actors

| Actor | Notes |
|-------|-------|
| Chaotic Eclipse (Nightmare-Eclipse) | PoC author; prior Windows LPE researcher |
| Ransomware operators | Rapid LPE weaponization is standard practice; expect use in kill chains within 1–2 weeks of PoC |
| APT clusters with Windows initial access | SYSTEM escalation enables Falcon sensor tampering, improving attacker persistence |

## References

- [The Register: FalconFlank CrowdStrike Falcon 0-Day PoC (2026-09-03)](https://www.theregister.com/security/2026/09/03/prolific-microsoft-0-day-hunter-drops-crowdstrike-falcon-exploit-poc/5294318)
- [Abstract Security: FalconFlank Detection Guidance](https://www.abstract.security/blog/chaotic-eclipse-releases-crowdstrike-falcon-zero-day-falconflank-detection-guidance)
- [SOCRadar: FalconFlank Analysis](https://socradar.io/blog/falconflank-crowdstrike-falcon-0day-poc/)
- [Threat Intel Report: FalconFlank](../threat-intel/2026-09-03_chaotic-eclipse-falconflank-crowdstrike-falcon-lpe-poc.md)
- [MITRE ATT&CK T1068](https://attack.mitre.org/techniques/T1068/)
- [MITRE ATT&CK T1562.001](https://attack.mitre.org/techniques/T1562/001/)
