# AuditTeam OpsAgent kvcore.sys BYOVD EDR Kill

## Description

Detects AuditTeam's OpsAgent ransomware framework deploying the legitimately signed Beijing Jiangmin Antivirus kernel driver (`kvcore.sys`) as a BYOVD (Bring Your Own Vulnerable Driver) weapon to terminate approximately 220 security tool processes (Microsoft Defender, ESET, Kaspersky, Sysmon, Splunk agents, database services) via the `\KvCorePortX0` kernel filter port before ransomware deployment.

Specifically detects: (1) kvcore.sys kernel driver service installation on hosts that do not operate Jiangmin Antivirus software; (2) msiexec.exe or notepad.exe running from non-standard paths indicating process injection (OpsAgent uses these as runtime C2 hosts); (3) Sysmon Event ID 6 kernel driver load for kvcore.sys.

False positives: Organizations legitimately running Beijing Jiangmin KV Antivirus products will generate detection (1); tune by host allowlist. Detections (2) and (3) are low false positive in environments without Jiangmin AV.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Tactic ID | TA0005 |
| Technique | Impair Defenses: Disable or Modify Tools |
| Technique ID | T1562.001 |

**Secondary Techniques:** T1543.003 (Windows Service — driver deployment), T1036.004 (Masquerading — impersonating AV driver), T1055 (Process Injection — msiexec/notepad C2 hosts), T1486 (Data Encrypted for Impact — ransomware payload), T1490 (Inhibit System Recovery — shadow copy deletion)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Actions on Objectives |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Services
  where (Services.service_path="*kvcore*" OR Services.service_path="*KvCore*"
         OR Services.service_name="*kvcore*" OR Services.service_name="*KvCore*"
         OR Services.service_name="*jiangmin*" OR Services.service_name="*KvCorePort*")
  by Services.dest Services.service_name Services.service_path Services.start_mode Services.user
| `drop_dm_object_name(Services)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest service_name service_path start_mode user risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| kvcore.sys or KvCorePortX0 service registration | 90 | Jiangmin AV driver deployment on a non-Jiangmin host is a strong BYOVD indicator; AuditTeam-specific TTP per Kaspersky GReAT |
| msiexec.exe or notepad.exe running from non-system paths | 80 | OpsAgent injects into these processes as C2 hosts; standard paths are C:\Windows\System32\ only |
| Mass security process termination (20+ kills in 60 s) | 95 | Near-certain pre-ransomware defense disarmament; correlate with BYOVD driver load |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| AuditTeam | [Kaspersky GReAT Securelist Report](https://securelist.com/auditteam-opsagent-forced-audit/122031/) |

## References

- [Kaspersky GReAT: The Forced Audit — AuditTeam OpsAgent](https://securelist.com/auditteam-opsagent-forced-audit/122031/)
- [Kaspersky Press Release: AuditTeam Ransomware Campaign](https://www.kaspersky.com/about/press-releases/kaspersky-uncovers-auditteam-ransomware-campaign-spanning-europe-asia-and-africa)
- [MITRE ATT&CK T1562.001 — Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
- [MITRE ATT&CK T1543.003 — Create or Modify System Process: Windows Service](https://attack.mitre.org/techniques/T1543/003/)
