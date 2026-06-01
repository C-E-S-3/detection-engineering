---
scraped_at: 2026-06-01T00:00:00Z
source_url: https://www.bleepingcomputer.com/news/security/fbi-warns-of-silent-ransom-group-in-person-data-theft-attacks/
report_type: threat-intel
severity: high
title: "FBI Flash: Silent Ransom Group (Luna Moth) Escalates Law Firm Attacks Using Vishing, Remote Access Tools, and In-Person Intrusion"
---

## 1. IOCs

No file hashes, malicious domains, or C2 IP addresses are associated with Silent Ransom Group campaigns — the group operates exclusively with **legitimate remote administration and file transfer tools**, leaving minimal traditional IOC signatures.

**Behavioral / Tool-Based IOCs:**

| Indicator Type | Value | Context |
|---------------|-------|---------|
| Process | `rclone.exe` or renamed `rclone` variants | Used for bulk data exfiltration to cloud storage |
| Process | `WinSCP.exe` | Used for data exfiltration via SFTP/SCP |
| Process | `ZohoAssist.exe` | Remote access tool installed after vishing call |
| Process | `syncrosetup.exe` / Syncro MSP | Remote access tool installed after vishing call |
| Process | `AnyDesk.exe` | Remote access tool used for persistence |
| Process | `Splashtop.exe` | Remote access tool used for persistence |
| Process | `AteraAgent.exe` | Remote access tool used for persistence |
| USB Device Event | Unregistered portable storage device inserted by visitor | Physical intrusion vector — "IT tech" inserts USB to "create a backup" |

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1566.004 | Phishing: Voice Phishing (Vishing) | Actors impersonate IT personnel via phone calls to convince employees to initiate a remote desktop session or install a RAT |
| Initial Access | T1566.001 | Phishing: Spearphishing Attachment | Phishing emails precede or accompany vishing calls; lures reference an IT alert or security incident |
| Initial Access | T1091 | Replication Through Removable Media | If remote access attempts fail, a physical operative attends the target location, claims to be IT support, and inserts a USB device to "image the machine" or "create a backup" |
| Execution | T1204.002 | User Execution: Malicious File | Victim is instructed to download and run a remote access tool presented as a legitimate IT utility |
| Persistence | T1219 | Remote Access Software | Legitimate RATs (Zoho Assist, Syncro, AnyDesk, Splashtop, Atera) installed under the guise of IT support; persist across reboots |
| Collection | T1074.001 | Data Staged: Local Data Staging | Sensitive data is staged on the local system before exfiltration |
| Exfiltration | T1048.002 | Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | WinSCP or Rclone used to transfer staged data to attacker-controlled cloud storage over SFTP/HTTPS |
| Impact | T1657 | Financial Theft (Extortion) | SRG does not encrypt files; instead threatens to publish or sell stolen data unless a ransom is paid |

**Attack Chain:**
1. Actors identify target employees at law firms (particularly those who handle sensitive client matters or have elevated system access).
2. Actors send a phishing email claiming a security incident or IT issue affecting the employee's account, urging them to call the help desk.
3. The employee calls the attacker-controlled phone number posing as IT support, or the attacker calls the employee directly.
4. While on the call, the attacker instructs the employee to grant a remote desktop session via a legitimate tool (Zoho Assist, AnyDesk, etc.).
5. With remote access established, the actor enumerates and stages sensitive data (legal documents, client records, financial data).
6. Data is exfiltrated using WinSCP or Rclone to cloud storage controlled by the attacker.
7. **Physical escalation path:** If remote access is denied, SRG dispatches an operative to the target office posing as an IT technician, who inserts a USB device and extracts data directly.
8. SRG publishes victim data on their leak site and demands payment to prevent further publication or sale.

## 3. Malware & Tools

| Tool | Type | Description |
|------|------|-------------|
| Rclone | Legitimate utility (abused) | Open-source command-line cloud sync tool; used by SRG to bulk-exfiltrate data; often renamed or run from non-standard paths to evade detection |
| WinSCP | Legitimate utility (abused) | SFTP/SCP Windows client; used for data exfiltration |
| Zoho Assist | Legitimate RAT (abused) | Cloud-based remote support tool; installed during vishing call |
| Syncro MSP | Legitimate RAT (abused) | MSP remote management platform; installed during vishing call |
| AnyDesk | Legitimate RAT (abused) | Commercial remote desktop tool; persistent across reboots |
| Splashtop | Legitimate RAT (abused) | Commercial remote access tool; persistent across reboots |
| Atera | Legitimate RAT (abused) | MSP platform with remote access; installed via social engineering |

## 4. Threat Actor / Campaign Attribution

| Attribute | Detail |
|-----------|--------|
| Actor Name | Silent Ransom Group (SRG) |
| Aliases | Luna Moth, Chatty Spider, UNC3753 |
| Active Since | At least 2022 |
| Motivation | Financially motivated — data theft and extortion without encryption |
| Primary Targets | Law firms (U.S.); previously healthcare organizations |
| Scale (2026) | 100+ confirmed intrusions as of Spring 2026; 38+ law firms with data published on leak site |
| FBI Flash | FLASH-20260526-01 (TLP:CLEAR), published May 26, 2026 |

**Key escalation in Spring 2026:**
- SRG activity surged sharply in early 2026, with attack counts exceeding 100 confirmed intrusions
- The group introduced **physical in-person intrusion** as a fallback when remote access attempts fail — operatives pose as IT staff and insert USB devices directly at the victim's workplace
- This physical component is unprecedented among data-extortion groups

## 5. Splunk Detection Searches

```spl
| comment "Search 1: Rclone or WinSCP invocation with cloud-sync arguments — SRG exfiltration activity"
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
    match(process,"(?i)(sync|copy|move|ls).*(remote|sftp|s3|onedrive|mega|dropbox|b2)"), 90,
    match(process,"(?i)(rclone|winscp)"), 75,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

```spl
| comment "Search 2: Remote access tool spawned outside normal IT provisioning parents — SRG RAT installation via vishing"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN 
    ("ZohoAssist.exe", "ZohoMeeting.exe", "syncrosetup.exe", "AnyDesk.exe",
     "Splashtop.exe", "AteraAgent.exe", "TeamViewer.exe", "ScreenConnect.exe")
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
| comment "Search 3: USB storage device insertion outside business hours — SRG physical intrusion indicator"
index=wineventlog EventCode=2003 OR EventCode=2100
| where match(_raw,"(?i)(disk|usb|removable|storage)")
| eval hour=strftime(_time,"%H")
| where (hour < 7 OR hour > 20)
| stats count values(EventCode) as event_codes min(_time) as firstTime max(_time) as lastTime
  by host, _raw
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| table firstTime lastTime host event_codes count risk_score
```

```spl
| comment "Search 4: Rclone network connections to cloud storage providers — corroborate exfil activity in network telemetry"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.app="rclone" 
    OR (All_Traffic.dest_port IN (22, 443, 21)
        AND All_Traffic.bytes_out > 10000000)
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.bytes_out All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=if(bytes_out > 100000000, 90, 70)
| where risk_score >= 70
| table firstTime lastTime src dest dest_port bytes_out app risk_score
```

**Tuning notes:**
- Search 1 is the primary detection: Rclone with cloud-sync arguments is a near-certain indicator of SRG exfiltration. Legitimate IT use of Rclone is uncommon in legal environments; create a baseline allowlist of authorized use.
- Search 2 will generate false positives in environments with legitimate MSP management tooling. Tune by filtering `dest` values that are enrolled in your official MSP/IT management platform.
- Search 3 detects USB storage insertion events outside business hours; tune the time window to your organization's business hours.
- Search 4 requires network traffic metadata with application identification (e.g., Palo Alto, Fortinet, or CrowdStrike Network Containment data). Filter known backup and sync services if used legitimately.

## 6. Executive Summary

On May 26, 2026, the FBI published Flash FLASH-20260526-01 (TLP:CLEAR) warning that Silent Ransom Group (SRG) — also known as Luna Moth and Chatty Spider — has dramatically escalated its targeting of U.S. law firms. BleepingComputer covered the advisory the following day, noting that SRG has compromised over 100 organizations in 2026 alone, with data from at least 38 law firms publicly leaked.

SRG operates a **data-theft-and-extortion** model with no ransomware encryption. The group uses exclusively legitimate tools (remote access software, Rclone, WinSCP) to avoid triggering antimalware products, making detection extremely difficult using signature-based approaches.

Most notably, SRG has introduced a new physical intrusion vector: when remote access attempts fail, the group dispatches operatives to the target location. These operatives pose as IT support staff, gain physical access to employee workstations, and insert USB storage devices to extract data — a technique with no precedent among currently active data-extortion groups.

**Immediate actions:**
1. Alert staff — especially at law firms, healthcare, and financial organizations — to be suspicious of unsolicited IT phone calls; establish out-of-band verification procedures before granting remote access.
2. Block or alert on execution of Rclone and WinSCP by non-IT-approved users; monitor for Rclone command lines containing cloud-sync operations.
3. Audit which remote access tools (AnyDesk, Zoho, Splashtop, Atera, Syncro) are installed in your environment; remove unauthorized instances.
4. Monitor USB storage insertion events, particularly outside business hours or from unregistered devices.
5. Consider requiring visitor escorts and sign-in procedures for anyone claiming to be an IT technician.

## References

- [BleepingComputer — FBI warns of Silent Ransom Group in-person data theft attacks (2026-05-27)](https://www.bleepingcomputer.com/news/security/fbi-warns-of-silent-ransom-group-in-person-data-theft-attacks/)
- [FBI Flash FLASH-20260526-01 (TLP:CLEAR) — Silent Ransom Group (2026-05-26)](https://www.ic3.gov/CSA/2026/260526.pdf)
- [Help Net Security — SRG law firm social engineering (2026-05-27)](https://www.helpnetsecurity.com/2026/05/27/fbi-silent-ransom-group-law-firms-social-engineering/)
- [Unit 42 — Luna Moth Callback Phishing Campaign](https://unit42.paloaltonetworks.com/luna-moth-callback-phishing/)
- [MITRE ATT&CK T1566 — Phishing](https://attack.mitre.org/techniques/T1566/)
- [MITRE ATT&CK T1219 — Remote Access Software](https://attack.mitre.org/techniques/T1219/)
- [MITRE ATT&CK T1048 — Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
