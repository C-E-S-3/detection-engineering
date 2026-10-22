# SafePay Ransomware — ShareFinder.ps1 Active Directory Share Enumeration

## Description

Detects PowerShell execution of ShareFinder.ps1 and related PowerView/PowerSploit functions used by SafePay ransomware operators during pre-encryption reconnaissance. SafePay actors run ShareFinder.ps1 (part of PowerSploit/PowerView) via PowerShell to enumerate all SMB file shares accessible in the Active Directory environment; the results are used to identify targets for PsExec-based lateral movement and ransomware deployment. This technique (T1135 Network Share Discovery via PowerShell T1059.001) is a high-confidence pre-ransomware signal. False positives are possible from legitimate penetration testing, red team exercises, and AD auditing tools that invoke the same PowerView functions. Correlate with other ransomware precursor behaviors (backup agent termination, shadow copy deletion, PsExec lateral movement) for highest confidence.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Execution |
| Tactic ID | TA0002 |
| Technique | Command and Scripting Interpreter: PowerShell |
| Technique ID | T1059.001 |

Secondary tactic/technique: TA0007 Discovery / T1135 (Network Share Discovery) — this is the operational objective of the PowerShell execution.

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name IN ("powershell.exe","pwsh.exe"))
    AND (Processes.process IN ("*ShareFinder*","*Invoke-ShareFinder*","*Find-DomainShare*","*Get-NetFileServer*","*Invoke-FileFinder*"))
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process,"(?i)invoke-sharefinder"), 92,
    match(process,"(?i)find-domainshare"), 90,
    match(process,"(?i)sharefinder"), 88,
    match(process,"(?i)get-netfileserver"), 82,
    match(process,"(?i)invoke-filefinder"), 80,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| `Invoke-ShareFinder` command in PowerShell commandline | 92 | Direct match to SafePay ransomware TTP per CISA AA26-293A; no benign use case in production |
| `Find-DomainShare` (PowerView alias) | 90 | PowerView domain share enumeration function; high-confidence offensive recon |
| Generic `ShareFinder` string | 88 | Matches script file loads and variations; high-confidence offensive tooling |
| `Get-NetFileServer` PowerView function | 82 | Enumerates file servers with active shares; offensive recon function |
| `Invoke-FileFinder` | 80 | Searches shares for files of interest; commonly used with ShareFinder in ransomware pre-encryption workflow |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| SafePay Ransomware | [CISA AA26-293A — #StopRansomware: SafePay Ransomware](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a) |
| Multiple ransomware groups using PowerSploit/PowerView | [MITRE ATT&CK T1135 — Network Share Discovery](https://attack.mitre.org/techniques/T1135/) |

## References

- [CISA Advisory AA26-293A — #StopRansomware: SafePay Ransomware](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a)
- [IC3 CSA 261020 — StopRansomware: SafePay Ransomware](https://www.ic3.gov/CSA/2026/261020.pdf)
- [PowerSploit/PowerView — Invoke-ShareFinder](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
- [MITRE ATT&CK T1135 — Network Share Discovery](https://attack.mitre.org/techniques/T1135/)
- [MITRE ATT&CK T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)
