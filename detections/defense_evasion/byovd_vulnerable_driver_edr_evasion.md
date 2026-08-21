# BYOVD — Bring Your Own Vulnerable Driver for EDR Evasion

## Description

Detects the Bring Your Own Vulnerable Driver (BYOVD) technique where adversaries load a legitimate but vulnerable signed kernel driver to terminate or disable endpoint detection and response (EDR) processes at the kernel level. This bypasses userspace-based EDR hooks and process-protection mechanisms.

The detection correlates suspicious driver/service installation activity (via `sc.exe`, `reg.exe`, or `fltMC.exe`) with subsequent process kills of security software. A driver load alone is not suspicious; the correlation with security tool process termination is the key signal.

Common false positive sources: legitimate software installers that load drivers (printer drivers, VPN clients, hardware utilities). Tune by excluding known-good driver names and service names from your environment.

UAT-10147 SPECTRE (August 2026) is a documented in-the-wild example of this technique combined with a Linux rootkit.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Tactic ID | TA0005 |
| Technique | Exploitation for Defense Evasion |
| Technique ID | T1211 |
| Sub-technique (secondary) | Impair Defenses: Disable or Modify Tools (T1562.001) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name="sc.exe" OR Processes.process_name="fltMC.exe")
    (Processes.process="*binpath*" OR Processes.process="*create*" OR Processes.process="*unload*")
    by Processes.dest Processes.user Processes.parent_process_name
       Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| rename dest as host_driver_load, user as user_driver_load, firstTime as driver_load_time
| join host_driver_load
    [| tstats `security_content_summariesonly` count min(_time) as kill_firstTime max(_time) as kill_lastTime
        from datamodel=Endpoint.Processes
        where (Processes.process_name IN ("MsMpEng.exe","SentinelAgent.exe","CSFalconService.exe",
            "cb.exe","CybereasonActiveProbe.exe","bdservicehost.exe","kavfswp.exe","avp.exe"))
        by Processes.dest Processes.process_name
    | `drop_dm_object_name(Processes)`
    | rename dest as host_driver_load, process_name as killed_security_process]
| eval risk_score=case(
    isnotnull(killed_security_process), 95,
    1=1, 40)
| where risk_score >= 40
| table driver_load_time kill_firstTime kill_lastTime host_driver_load user_driver_load
        process_name process killed_security_process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Driver/service installation correlated with EDR process kill on same host | 95 | Near-certain BYOVD EDR evasion — kernel-level driver load followed by security tool termination |
| Driver/service installation only (no EDR kill observed) | 40 | Anomalous driver load; needs analyst triage to determine legitimacy |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| UAT-10147 (SPECTRE) | [Cisco Talos IOCs](https://github.com/Cisco-Talos/IOCs/blob/main/2026/08/UAT-10147%20deploys%20SPECTRE.json) |
| Lazarus Group | [MITRE ATT&CK G0032](https://attack.mitre.org/groups/G0032/) |
| BlackByte ransomware | [MITRE ATT&CK T1211](https://attack.mitre.org/techniques/T1211/) |
| AvosLocker ransomware | [CISA Advisory](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-284a) |

## References

- [MITRE ATT&CK T1211 — Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211/)
- [MITRE ATT&CK T1562.001 — Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
- [Cisco Talos: UAT-10147 deploys SPECTRE (August 2026)](https://github.com/Cisco-Talos/IOCs/blob/main/2026/08/UAT-10147%20deploys%20SPECTRE.json)
- [ESET Research: BYOVD technique overview](https://www.welivesecurity.com/en/eset-research/byovd-attacks-kernel-exploitation/)
