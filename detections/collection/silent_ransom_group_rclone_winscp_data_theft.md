# Silent Ransom Group (Luna Moth) Rclone and WinSCP Data Exfiltration

## Description

Detects data exfiltration and remote access tool usage patterns associated with Silent Ransom Group (SRG), also known as Luna Moth and Chatty Spider. SRG is a financially motivated extortion group that exclusively uses legitimate software — Rclone, WinSCP, and commercial remote access tools (AnyDesk, Zoho Assist, Splashtop, Syncro, Atera) — to avoid triggering antimalware products. The group targets law firms and professional services organizations, stealing data and extorting victims without deploying ransomware encryption.

In Spring 2026, SRG escalated to over 100 confirmed intrusions including a novel physical component: operatives are dispatched to victims' offices posing as IT support staff, inserting USB devices directly into workstations when remote access attempts fail.

**False positive sources:** Legitimate IT administration using Rclone or WinSCP for authorized cloud backup/sync. Tune by filtering known IT service accounts and approved backup destinations via lookup table. Remote access tools are legitimately used by MSP/IT departments — baseline authorized installs before alerting.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Collection |
| Tactic ID | TA0009 |
| Technique | Data Staged: Local Data Staging |
| Technique ID | T1074.001 |
| Secondary Tactic | Exfiltration |
| Secondary Technique | Exfiltration Over Alternative Protocol |
| Secondary Technique ID | T1048.002 |
| Secondary Technique | Remote Access Software |
| Secondary Technique ID | T1219 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

```spl
| comment "Query 1: Rclone or WinSCP execution with cloud-sync arguments — SRG data exfiltration"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name IN ("rclone.exe", "rclone")
    OR (Processes.process_name IN ("cmd.exe", "powershell.exe")
        AND (Processes.process="*rclone*" OR Processes.process="*winscp*")))
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process,"(?i)(sync|copy|move).*(remote|sftp|s3|onedrive|mega|dropbox|b2|gdrive)"), 90,
    match(process,"(?i)(rclone|winscp)"), 75,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

```spl
| comment "Query 2: Unauthorized remote access tool installation — SRG RAT installation via vishing"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN
    ("ZohoAssist.exe", "ZohoMeeting.exe", "syncrosetup.exe", "Syncro.exe",
     "AnyDesk.exe", "Splashtop.exe", "AteraAgent.exe", "ScreenConnect.exe")
    AND NOT Processes.parent_process_name IN
    ("msiexec.exe", "services.exe", "svchost.exe", "TrustedInstaller.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    parent_process_name IN ("explorer.exe", "cmd.exe", "powershell.exe"), 85,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

```spl
| comment "Query 3: Large outbound data transfer via Rclone process — corroborate exfil in network telemetry"
| tstats `security_content_summariesonly` sum(All_Traffic.bytes_out) as total_bytes_out
    count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_port IN (22, 443, 21, 2049)
    AND All_Traffic.bytes_out > 5000000
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.process
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process,"(?i)(rclone|winscp)") AND total_bytes_out > 100000000, 90,
    match(process,"(?i)(rclone|winscp)") AND total_bytes_out > 10000000, 80,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime src dest dest_port process total_bytes_out risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Rclone with cloud-sync args targeting cloud storage provider | 90 | Near-certain exfiltration; Rclone to cloud storage is SRG's primary method |
| Rclone or WinSCP execution without cloud-sync args | 75 | Potential staging; warrants review in legal/professional services environments |
| Remote access tool launched from Explorer/cmd/PowerShell | 85 | RAT installed manually via vishing call, not through authorized IT provisioning |
| Remote access tool launched from non-IT parent | 70 | Possibly authorized but warrants validation |
| Rclone/WinSCP + network exfil > 100MB to external host | 90 | Active exfiltration in progress |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Silent Ransom Group (SRG) / Luna Moth / Chatty Spider / UNC3753 | [FBI Flash FLASH-20260526-01 (TLP:CLEAR)](https://www.ic3.gov/CSA/2026/260526.pdf), [BleepingComputer (2026-05-27)](https://www.bleepingcomputer.com/news/security/fbi-warns-of-silent-ransom-group-in-person-data-theft-attacks/) |

## References

- [BleepingComputer — FBI warns of SRG in-person data theft attacks (2026-05-27)](https://www.bleepingcomputer.com/news/security/fbi-warns-of-silent-ransom-group-in-person-data-theft-attacks/)
- [FBI Flash FLASH-20260526-01 — Silent Ransom Group (2026-05-26)](https://www.ic3.gov/CSA/2026/260526.pdf)
- [Unit 42 — Luna Moth Callback Phishing Campaign](https://unit42.paloaltonetworks.com/luna-moth-callback-phishing/)
- [MITRE ATT&CK T1074 — Data Staged](https://attack.mitre.org/techniques/T1074/)
- [MITRE ATT&CK T1048 — Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
- [MITRE ATT&CK T1219 — Remote Access Software](https://attack.mitre.org/techniques/T1219/)
