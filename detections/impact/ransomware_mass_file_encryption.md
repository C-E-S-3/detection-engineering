# Ransomware Mass File Encryption — Data Encrypted for Impact

## Description

Detects the rapid, high-volume file modification and rename activity that is the hallmark of ransomware encryption activity. Modern ransomware (Qilin/AGENDA, Medusa, LockBit, Akira/REDBIKE, RansomHub) typically touches thousands of files per minute, renames them with a new extension, and drops ransom notes. This detection uses statistical thresholds on file modification events per host per minute. Common false positives: bulk file migrations, backup software writing large datasets, file indexing services, antivirus scanning; tune exclusions by process name for known backup agents (Veeam, Backup Exec, Windows Backup).

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Impact |
| Tactic ID | TA0040 |
| Technique | Data Encrypted for Impact |
| Technique ID | T1486 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.action IN ("created","modified","renamed")
    AND NOT Filesystem.process_name IN ("veeam*","veeamguesthelper.exe","beremote.exe",
        "searchindexer.exe","antivirus*","msiexec.exe","svchost.exe","trustedinstaller.exe")
  by Filesystem.dest Filesystem.user Filesystem.process_name _time
| `drop_dm_object_name(Filesystem)`
| bucket _time span=1m
| stats count as file_ops_per_min by dest user process_name _time
| where file_ops_per_min > 200
| eval risk_score=case(
    file_ops_per_min > 1000, 95,
    file_ops_per_min > 500,  90,
    file_ops_per_min > 200,  80,
    1=1, 70)
| stats min(risk_score) as risk_score max(file_ops_per_min) as peak_file_ops
    min(_time) as firstTime max(_time) as lastTime
  by dest user process_name
| where risk_score >= 80
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user process_name peak_file_ops risk_score
```

**Supplemental: Ransom note file creation**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.action="created"
    AND (Filesystem.file_name IN ("README.txt","HOW_TO_DECRYPT.txt","!README!.txt",
         "RECOVER_FILES.txt","FILES_ENCRYPTED.txt","PAYMENT_INSTRUCTIONS.txt",
         "READ_ME_PLEASE.txt","YOUR_FILES_ARE_ENCRYPTED.txt")
         OR Filesystem.file_name="*DECRYPT*" OR Filesystem.file_name="*RANSOM*"
         OR Filesystem.file_name="*RESTORE*")
  by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| eval risk_score=case(
    match(file_name, "(?i)decrypt|ransom|restore"), 90,
    1=1, 85)
| where risk_score >= 85
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user process_name file_path file_name risk_score
```

**Supplemental: Volume Shadow Copy deletion (anti-recovery)**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name="vssadmin.exe" AND Processes.process="*delete*shadows*")
     OR (Processes.process_name="wmic.exe" AND Processes.process="*shadowcopy*delete*")
     OR (Processes.process_name="powershell.exe" AND Processes.process="*Get-WmiObject*Win32_ShadowCopy*Delete*")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| eval risk_score=95
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| >1000 file ops/min from single process | 95 | Near-certain ransomware encryption; legitimate tools rarely exceed this threshold |
| >500 file ops/min | 90 | High-confidence encryption activity; correlate with renamed extensions |
| >200 file ops/min | 80 | Suspicious; may be aggressive backup or indexing, investigate process |
| Ransom note file creation (known names) | 85-90 | Definitive ransomware indicator; immediately escalate |
| VSS/shadow copy deletion | 95 | Anti-recovery technique; always pre-ransomware execution |

## Associated Threat Actors

| Actor | Relationship to Detection |
|-------|--------------------------|
| Qilin Ransomware (AGENDA) | #1 most active ransomware 2025; encrypts VMware ESXi datastores and Windows hosts; deploys EDR killer first |
| Medusa Ransomware | Double-extortion operator; targets all sectors; SMBExec/WMIExec lateral movement before encryption |
| LockBit (Gold Mystic) | Largest RaaS affiliate network; self-spreading encryption capability |
| Akira (REDBIKE) | Targets backup infrastructure and virtualization management planes (M-Trends 2026) |
| RansomHub | Emerging RaaS operation targeting critical infrastructure |
| Conti (Wizard Spider) / Successor Groups | Royal/BlackSuit, Black Basta — heritage encryption TTPs |

## References

- [Google Threat Intelligence - M-Trends 2026](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026/)
- [Cisco Talos - Ransomware in 2025: Blending In Is the Strategy](https://blog.talosintelligence.com/ransomware-in-2025-blending-in-is-the-strategy/)
- [CISA - StopRansomware: Medusa](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a)
- [MITRE ATT&CK - T1486 Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK - T1490 Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
