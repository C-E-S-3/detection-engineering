# Qilin EDR Killer — Security Tool Process Termination via Mass Driver Enumeration

## Description

Detects EDR killer tooling associated with Qilin ransomware affiliates that targets over 300 EDR and endpoint security drivers to blind security tools before ransomware deployment. The tool enumerates running security processes and loaded drivers, then terminates them using BYOVD or direct process kill techniques. Common false positives: legitimate IT operations terminating security software for maintenance; validate against change management records and correlate with other pre-ransomware indicators.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Tactic ID | TA0005 |
| Technique | Impair Defenses: Disable or Modify Tools |
| Technique ID | T1562.001 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("EDRKiller.exe", "EDRSandblast.exe", "Terminator.exe", "KillAV.exe")
     OR (Processes.parent_process_name IN ("cmd.exe","powershell.exe","wscript.exe")
         AND Processes.process="*taskkill*" AND Processes.process="*/F*")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| eval risk_score=case(
    match(process_name, "(?i)EDRKiller|EDRSandblast"), 95,
    match(process_name, "(?i)Terminator|KillAV"), 90,
    match(process, "(?i)taskkill.*\/F"), 65,
    1=1, 50)
| where risk_score >= 50
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

**Supplemental: Geo-fencing locale check (Qilin pre-execution)**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name="powershell.exe" OR Processes.process_name="cmd.exe")
    AND (Processes.process="*Get-Culture*" OR Processes.process="*GetCultureInfo*"
         OR Processes.process="*locale*" OR Processes.process="*LANGUAGE*")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| eval risk_score=case(
    match(process, "(?i)GetCultureInfo|Get-Culture"), 60,
    match(process, "(?i)locale"), 50,
    1=1, 40)
| where risk_score >= 50
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Known EDR killer binary names (EDRKiller.exe, EDRSandblast.exe) | 95 | Near-certain TP; these are dedicated offensive EDR termination tools |
| Known EDR killer aliases (Terminator, KillAV) | 90 | High-confidence; widely used in pre-ransomware workflows |
| Mass forced process termination via taskkill /F | 65 | Suspicious but possible in admin contexts; correlate with other indicators |
| Locale/culture enumeration from scripting engine | 50-60 | Qilin geo-fencing check; low confidence alone, elevates composite score |

## Associated Threat Actors

| Actor | Relationship to Detection |
|-------|--------------------------|
| Qilin Ransomware Group | Primary actor; affiliates deploy EDR killer malware targeting 300+ EDR drivers before ransomware execution, observed in Japan targeting manufacturing and healthcare |
| Scattered Spider (UNC3944) | Also known to use BYOVD and EDR-killing techniques, confirmed Qilin affiliate |
| LockBit Affiliates | EDR termination tooling (GMER, Process Hacker) used in similar pre-ransomware workflows |

## References

- [Cisco Talos - Qilin Ransomware in Japan 2025](https://blog.talosintelligence.com/an-overview-of-ransomware-threats-in-japan-in-2025-and-early-detection-insights-from-qilin-cases/)
- [MITRE ATT&CK - T1562.001 Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
- [Sophos - Qilin Ransomware](https://news.sophos.com/en-us/2023/07/17/qilin-opportunistic-but-not-so-amateur/)
