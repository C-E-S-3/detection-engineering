---
scraped_at: "2026-08-02T00:00:00Z"
source_url: https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/
report_type: threat-intel
severity: high
title: "Microsoft TI: CaptiveCrunch — APT29 / Midnight Blizzard Targets Travelers Worldwide via Microsoft 365 Impersonation (July 2026)"
---

# CaptiveCrunch — APT29 / Midnight Blizzard Targets Travelers Worldwide

Microsoft Threat Intelligence published July 31, 2026 detailing "CaptiveCrunch," a campaign by APT29 (also tracked as Midnight Blizzard, Storm-2945, NOBELIUM, and per updated GTIG taxonomy: ICE RELIC) targeting travelers worldwide. The campaign uses Microsoft 365 and Entra ID impersonation domains to deliver the CornFlake RAT and ChocoShell PowerShell infostealer via credential phishing and malware lures.

## 1. IOCs

### Domains (Microsoft 365 / Entra ID impersonation)
| Indicator | Registered | Context |
|-----------|------------|---------|
| `ms365-device[.]com` | 2026-07-23 | Microsoft Entra device registration lure |
| `ms365-live[.]com` | 2026-05-14 | Microsoft 365 OneDrive/Live impersonation |
| `m365-owa[.]com` | 2026-07-20 | Microsoft 365 Outlook Web App impersonation |
| `owa-ms365[.]com` | 2026-07-16 | Microsoft 365 Outlook Web App impersonation |
| `my-invite[.]org` | — | Maltrail-sourced lure domain; lower confidence |

### IP Addresses
| Indicator | Context |
|-----------|---------|
| `31.57.243.154` | Attacker infrastructure (multiple ports: 2000, 443) |
| `38.146.28.75` | Attacker infrastructure (ports 4000, 8443) |
| `38.146.28.132` | Attacker infrastructure (port 443) |
| `104.194.159.150` | Attacker infrastructure (port 443) |
| `107.189.26.194` | Attacker infrastructure (port 443) |
| `213.145.86.112` | ChocoShell C2 server |
| `138.197.202.81` | Maltrail-sourced (port 3000) |
| `138.68.160.124` | Maltrail-sourced (port 3000) |
| `165.22.146.161` | Maltrail-sourced (port 3000) |
| `216.126.224.95` | Maltrail-sourced (port 3000) |
| `31.172.83.142` | Maltrail-sourced (port 4000) |
| `84.200.154.162` | Maltrail-sourced (port 4000) |

### File Hashes (SHA256)
| Hash | Type | Malware |
|------|------|---------|
| `918fa52ae45ed60ba7cc8bdc99c3cbe9ab92e0375ec31fc05d0d4513be11c593` | PE/EXE | CornFlake RAT |
| `be99857449d2856dd5a84e21c8a3d5e0e01456adb44062ddec5a6b4970d8d42c` | PS1 | ChocoShell PowerShell infostealer |

## 2. Malware & Tools

**CornFlake RAT:** Remote access trojan delivered as the primary payload in CaptiveCrunch. Provides persistent remote control capability. First identified in this campaign.

**ChocoShell:** PowerShell-based infostealer. Harvests credentials, browser data, and sensitive files. Communicates to C2 server at `213.145.86.112`. Consistent with APT29's pattern of using lightweight, script-based secondary payloads to minimize forensic footprint.

## 3. Actor Attribution

**APT29** (Russian SVR — Foreign Intelligence Service)
- Microsoft: Midnight Blizzard, Storm-2945
- GTIG (updated July 2026): ICE RELIC
- Historic: NOBELIUM, The Dukes, Cozy Bear, UNC2452

APT29 has consistently targeted high-value credentials and intelligence data. The "travelers worldwide" targeting reflects an SVR intelligence priority: compromising individuals with access to sensitive government, diplomatic, and corporate information who may be using less-secure networks or devices while traveling. The rapid registration and deployment of near-identical M365 impersonation domains (four domains registered within a 10-week window) indicates dedicated operational resources for this campaign.

## 4. TTPs

| Tactic | Technique ID | Technique | Notes |
|--------|-------------|-----------|-------|
| Initial Access | T1566.002 | Phishing: Spearphishing Link | M365 impersonation domains lure credential entry |
| Initial Access | T1078 | Valid Accounts | Harvested credentials used for further access |
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | ChocoShell infostealer payload |
| Persistence | T1547 | Boot or Logon Autostart Execution | CornFlake RAT establishes persistence |
| Credential Access | T1056.003 | Input Capture: Web Portal Capture | AiTM-style credential harvesting via M365 lure pages |
| Credential Access | T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | ChocoShell browser credential harvesting |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | HTTPS C2 to `213.145.86.112` |
| Collection | T1560 | Archive Collected Data | Data staged before exfiltration |

## 5. Splunk Detections

### DNS query for CaptiveCrunch impersonation domains
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query IN ("ms365-device.com","ms365-live.com","m365-owa.com","owa-ms365.com","my-invite.org")
  by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, src, query, answer, count
```

### Network connection to CaptiveCrunch C2 IPs
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_ip IN ("31.57.243.154","38.146.28.75","38.146.28.132",
    "104.194.159.150","107.189.26.194","213.145.86.112","138.197.202.81",
    "138.68.160.124","165.22.146.161","216.126.224.95","31.172.83.142","84.200.154.162")
  by All_Traffic.src All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.bytes_out
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, src, dest_ip, dest_port, bytes_out, count
```

### PowerShell infostealer activity (ChocoShell indicators)
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name="powershell.exe"
    AND (Processes.process IN ("*WebClient*", "*DownloadString*", "*IEX*", "*Invoke-Expression*")
    OR Processes.process IN ("*213.145.86.112*"))
  by Processes.dest Processes.user Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, dest, user, process_name, process, count
```

### File hash match — CaptiveCrunch malware
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_hash IN (
    "918fa52ae45ed60ba7cc8bdc99c3cbe9ab92e0375ec31fc05d0d4513be11c593",
    "be99857449d2856dd5a84e21c8a3d5e0e01456adb44062ddec5a6b4970d8d42c"
  )
  by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.file_hash
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, dest, user, file_name, file_path, file_hash
```

## 6. Executive Summary

**Published:** July 31, 2026  
**Actor:** APT29 / Midnight Blizzard / ICE RELIC (Russian SVR)  
**Operation Name:** CaptiveCrunch  
**Targeting:** Travelers worldwide — high-value individuals in government, diplomatic, and corporate sectors  

APT29 deployed a cluster of Microsoft 365 and Entra ID impersonation domains with rapid turnover (four domains registered June–July 2026), targeting individuals who may connect to less-secured networks while traveling. The campaign delivers CornFlake RAT for persistent access and ChocoShell for immediate credential harvesting. The selection of travel-targeting aligns with SVR operational priorities: individuals traveling to Russia-adjacent regions or accessing sensitive diplomatic and government information while abroad. Organizations should alert employees about this campaign and consider monitoring for DNS queries to M365-lookalike domains.

## 7. References

- [Microsoft Threat Intelligence — CaptiveCrunch: Midnight Blizzard targets travelers worldwide](https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/)
- [Maltrail apt_duke.txt — APT29 CaptiveCrunch IOC feed](https://github.com/stamparm/maltrail/blob/master/trails/static/malware/apt_duke.txt)
- [GTIG — Updated Cyber Threat Actor Naming System (ICE RELIC = APT29)](https://cloud.google.com/blog/topics/threat-intelligence/updated-cyber-threat-actor-naming-system)
- [MITRE ATT&CK APT29](https://attack.mitre.org/groups/G0016/)
- [MITRE ATT&CK T1566.002 — Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
