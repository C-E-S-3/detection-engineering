# Storm-2570 / Ransomware Affiliate — ntdsutil NTDS.dit IFM Extraction

## Description

Detects `ntdsutil.exe` executing with Install From Media (IFM) arguments used to create a copy of the Active Directory NTDS.dit database, which contains all domain password hashes. The IFM method (`ntdsutil "ac i ntds" "ifm" "create full <path>"`) is the primary technique used by ransomware affiliates including Storm-2570 to dump domain credentials offline without alerting on direct LSASS access. This technique is also used by Hazy Scorpius, other ransomware pre-ransom operations, and red teams.

False positives: Legitimate domain controller backups or AD migration tasks may invoke ntdsutil with similar arguments. Verify the initiating user, parent process, and destination path; legitimate use is scheduled or change-managed, not spontaneous.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Credential Access |
| Tactic ID | TA0006 |
| Technique | OS Credential Dumping: NTDS |
| Technique ID | T1003.003 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name="ntdsutil.exe"
      AND (Processes.process IN ("*ifm*","*create full*","*ac i ntds*","*activate instance ntds*"))
    by Processes.dest Processes.user Processes.parent_process_name
       Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process,"(?i)create full"), 95,
    match(process,"(?i)ifm"), 90,
    match(process,"(?i)activate instance ntds|ac i ntds"), 85,
    true(), 75
)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score count
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| `ntdsutil` with `create full` argument | 95 | Direct IFM NTDS.dit extraction — near-certain credential dump |
| `ntdsutil` with `ifm` argument | 90 | IFM context established — highly suspicious |
| `ntdsutil` with `activate instance ntds` | 85 | AD instance activation pre-IFM dump |
| Any `ntdsutil.exe` execution | 75 | Uncommon in normal operations; warrants review |

Correlate with rclone, s5cmd, or RMM tool installation on the same host within 4 hours for elevated confidence of ransomware pre-exfil activity.

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Storm-2570 | [Microsoft Threat Intelligence (September 24, 2026)](https://www.microsoft.com/en-us/security/blog/2026/09/24/beyond-ransomware-tracking-storm-2570-consistent-tradecraft-across-deployments/) |
| Hazy Scorpius | Internal tracking — CVE-2026-12569 campaign, July 2026 |
| Qilin operators | [MITRE ATT&CK — Qilin](https://attack.mitre.org/software/S1079/) |
| DragonForce operators | [MITRE ATT&CK — DragonForce](https://attack.mitre.org/software/S1070/) |
| Various ransomware affiliates | [MITRE ATT&CK — T1003.003](https://attack.mitre.org/techniques/T1003/003/) |

## References

- [Microsoft Security Blog — Storm-2570 Tradecraft Analysis (September 24, 2026)](https://www.microsoft.com/en-us/security/blog/2026/09/24/beyond-ransomware-tracking-storm-2570-consistent-tradecraft-across-deployments/)
- [MITRE ATT&CK — T1003.003: OS Credential Dumping: NTDS](https://attack.mitre.org/techniques/T1003/003/)
- [Microsoft — ntdsutil reference](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc753343(v=ws.11))
