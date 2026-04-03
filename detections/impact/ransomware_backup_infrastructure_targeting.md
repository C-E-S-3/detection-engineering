# Ransomware Backup Infrastructure Targeting — Inhibit System Recovery

## Description

Detects ransomware pre-encryption activity specifically targeting backup infrastructure — backup agent termination, deletion of backup jobs, Veeam/Backup Exec/Windows Server Backup database tampering, and attacks against hypervisor management planes (VMware vCenter, ESXi). Threat actors increasingly destroy backup infrastructure before deploying ransomware to eliminate recovery options. AGENDA (Qilin) and REDBIKE (Akira) were specifically observed targeting virtualization management planes in Mandiant M-Trends 2026. Common false positives: legitimate backup maintenance windows; correlate with process lineage and non-standard execution times.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Impact |
| Tactic ID | TA0040 |
| Technique | Inhibit System Recovery |
| Technique ID | T1490 |

Secondary technique: T1485 (Data Destruction — backup database deletion)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name="net.exe" OR Processes.process_name="net1.exe")
    AND Processes.process IN ("*stop*veeam*","*stop*backup*","*stop*acronis*",
        "*stop*vss*","*stop*SQLsafe*","*stop*mssql*")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| eval risk_score=90
| append
    [| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
       from datamodel=Endpoint.Processes
       where Processes.process_name="wbadmin.exe"
         AND (Processes.process="*delete*" OR Processes.process="*disable*")
       by Processes.dest Processes.user Processes.parent_process_name
          Processes.process_name Processes.process Processes.process_id
     | `drop_dm_object_name(Processes)`
     | eval risk_score=95]
| append
    [| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
       from datamodel=Endpoint.Processes
       where Processes.process_name="bcdedit.exe"
         AND (Processes.process="*recoveryenabled*no*" OR Processes.process="*bootstatuspolicy*ignoreallfailures*")
       by Processes.dest Processes.user Processes.parent_process_name
          Processes.process_name Processes.process Processes.process_id
     | `drop_dm_object_name(Processes)`
     | eval risk_score=95]
| where risk_score >= 90
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

**Supplemental: VMware ESXi — backup/snapshot destruction via esxcli/vim-cmd**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("esxcli","vim-cmd","vmkfstools")
    AND (Processes.process="*snapshot*delete*" OR Processes.process="*snapshot*removeall*"
         OR Processes.process="*vmsvc/snapshot*" OR Processes.process="*destroy*")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| eval risk_score=90
| where risk_score >= 90
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

**Supplemental: Veeam backup database deletion or job manipulation**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.action IN ("deleted","modified")
    AND (Filesystem.file_path="*\\Veeam\\Backup\\*" OR Filesystem.file_path="*\\Backup Exec\\*"
         OR Filesystem.file_path="*\\WindowsImageBackup\\*")
    AND NOT Filesystem.process_name IN ("VeeamBackup.exe","BackupExec.exe","wbengine.exe")
  by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| eval risk_score=85
| where risk_score >= 85
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user process_name file_path risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| wbadmin delete/disable (Windows backup) | 95 | Direct backup elimination; no legitimate use case during normal operations |
| bcdedit recovery disabled | 95 | Boot recovery disabled; standard ransomware anti-recovery TTP |
| Service stop for Veeam/Backup Exec/VSS | 90 | Backup agent termination preceding encryption |
| ESXi snapshot deletion via esxcli/vim-cmd | 90 | Hypervisor anti-recovery targeting VMware environments |
| Backup database files modified by non-backup process | 85 | Unauthorized tampering with backup metadata |

## Associated Threat Actors

| Actor | Relationship to Detection |
|-------|--------------------------|
| Qilin Ransomware (AGENDA) | Specifically targets backup infrastructure; destroys recovery capabilities before encryption (M-Trends 2026) |
| Akira (REDBIKE) | Targets virtualization management planes and backup infrastructure (M-Trends 2026) |
| Medusa Ransomware | Backup destruction is standard pre-encryption step; uses wbadmin and bcdedit |
| LockBit Affiliates | Documented Veeam exploitation and backup deletion via PowerShell |
| Conti / BlackSuit / Black Basta | Inherited Conti playbooks include backup elimination via net stop commands |

## References

- [Google Threat Intelligence - M-Trends 2026](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026/)
- [MITRE ATT&CK - T1490 Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- [MITRE ATT&CK - T1485 Data Destruction](https://attack.mitre.org/techniques/T1485/)
- [CISA - StopRansomware: Medusa](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a)
