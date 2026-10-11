# AhsayCBS CVE-2026-105134 — XMRig Cryptominer Masquerading as Microsoft Edge

## Description

Detects XMRig cryptominer components deployed through exploitation of AhsayCBS backup software (CVE-2026-105133 + CVE-2026-105134). After achieving unauthenticated SYSTEM-level code execution via the AhsayCBS Replication Receiver endpoint, attackers drop XMRig disguised as `edge.exe` or `msedge.exe` and persist it as a Windows service named `MicrosoftEdgeUpdateSvc`. The kernel driver `WinRing0x64.sys` is dropped for hardware-level Monero mining access.

The primary indicator is `edge.exe` or `msedge.exe` spawned by a Java or PowerShell process — legitimate Microsoft Edge is never spawned from Java runtimes. A secondary indicator is `WinRing0x64.sys` dropped outside of known hardware-monitoring tool directories.

False positives: Hardware monitoring tools (HWiNFO, AIDA64, OpenRGB, HWMonitor) legitimately load `WinRing0x64.sys`. Any Edge process spawned from an application framework rather than a browser or installer context warrants investigation.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Execution, Defense Evasion, Impact |
| Tactic ID | TA0002, TA0005, TA0040 |
| Technique | Masquerading: Match Legitimate Name or Location |
| Technique ID | T1036.005 |
| Sub-techniques | T1496 (Resource Hijacking), T1190 (Exploit Public-Facing Application) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Actions on Objectives |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name="edge.exe" OR Processes.process_name="msedge.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    like(lower(parent_process_name), "%java%"), 95,
    like(lower(parent_process_name), "%tomcat%"), 95,
    like(lower(parent_process_name), "%powershell%"), 90,
    like(lower(parent_process_name), "%cmd%"), 85,
    NOT like(lower(parent_process_name), "%msedge%")
      AND NOT like(lower(parent_process_name), "%edge%")
      AND NOT like(lower(parent_process_name), "%setup%")
      AND NOT like(lower(parent_process_name), "%install%")
      AND NOT like(lower(parent_process_name), "%update%"), 75,
    1=1, 30)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process process_path risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Parent is `java.exe` or `tomcat*.exe` | 95 | Critical — legitimate Edge is never spawned by a Java runtime; near-certain AhsayCBS exploitation |
| Parent is `powershell.exe` | 90 | High — PowerShell spawning an Edge-named process is almost always malicious masquerade |
| Parent is `cmd.exe` | 85 | High — Edge should not be spawned directly from a command prompt |
| Parent is not any Edge, setup, or installer process | 75 | High — Edge spawned from any unexpected parent warrants investigation |
| Any other parent | 30 | Low — potential false positive from legitimate update mechanisms |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown (AhsayCBS exploitation actors, October 2026) | [Huntress Blog — AhsayCBS CVE-2026-105133/105134](https://www.huntress.com/blog/ahsaycbs-flaws-exploit) |

## References

- [Huntress Blog — AhsayCBS Flaws Exploit](https://www.huntress.com/blog/ahsaycbs-flaws-exploit)
- [MITRE ATT&CK T1036.005 — Masquerading: Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005/)
- [MITRE ATT&CK T1496 — Resource Hijacking](https://attack.mitre.org/techniques/T1496/)
- [MITRE ATT&CK T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
