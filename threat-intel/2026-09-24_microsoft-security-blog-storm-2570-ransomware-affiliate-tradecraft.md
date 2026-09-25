---
scraped_at: "2026-09-25T00:00:00Z"
source_url: "https://www.microsoft.com/en-us/security/blog/2026/09/24/beyond-ransomware-tracking-storm-2570-consistent-tradecraft-across-deployments/"
report_type: threat-intel
severity: high
title: "Beyond the Ransomware: Tracking Storm-2570's Consistent Tradecraft Across Deployments"
---

# Microsoft Threat Intelligence — Storm-2570 Ransomware Affiliate Tradecraft (September 24, 2026)

## Executive Summary

Microsoft Threat Intelligence published a deep-dive on September 24, 2026 documenting **Storm-2570**, a ransomware affiliate tracked since April 2025 that operates across multiple RaaS ecosystems with a remarkably consistent post-compromise toolset. Unlike actor-specific TTPs tied to a single ransomware family, Storm-2570 deploys the same intrusion chain — commercial RMM tools, open-source credential harvesters, and cloud storage exfiltration — regardless of whether the final payload is **Qilin**, **DragonForce**, **Anubis**, or **BERT** ransomware. No concrete network IOCs (domains, IPs, file hashes) were published in this report; the value is actor-level TTP and toolset tracking.

---

## 1. IOCs

### Confirmed IOCs

**None published.** Microsoft's report is a tradecraft analysis. No file hashes, C2 domains, or IP addresses were included.

### Behavioral / Artifact Indicators

| Artifact | Value | Context |
|---|---|---|
| Tool | MeshAgent.exe | Primary RMM for persistent remote access |
| Tool | Atera.exe | Backup RMM tool |
| Tool | ScreenConnect | Backup RMM tool |
| Tool | Splashtop Streamer | Backup RMM tool |
| Tool | NinjaRMM | Backup RMM tool |
| Tool | Remotely_Agent.exe | Backup RMM tool |
| Tool | NetScan | Network discovery |
| Tool | netscan.exe (SoftPerfect Portable) | Network discovery |
| Tool | nmap | Network discovery |
| Tool | PsExec | Lateral tool transfer |
| Tool | Impacket | SMB lateral movement |
| Tool | NetExec | SMB lateral movement |
| Tool | Mimikatz | Credential dumping |
| Tool | LaZagne | Credential dumping |
| Tool | pypykatz | Credential dumping |
| Tool | ntdsutil.exe | NTDS.dit extraction |
| Tool | cloudflared.exe | Tunneling / defense evasion |
| Tool | ngrok | Tunneling / defense evasion |
| Tool | s5cmd | S3 exfiltration |
| Tool | rclone.exe | Cloud sync / exfiltration |
| Technique | ntdsutil `ac i ntds` `ifm` `create full <path>` | NTDS.dit dump via IFM snapshot |
| Technique | Defender real-time monitoring disabled | Defense impairment pre-encryption |
| Technique | Windows Defender exclusion paths added | Defense evasion before execution |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique | Sub | ID | Notes |
|---|---|---|---|---|
| Execution | System Services | Service Execution | T1569.002 | RMM tools deployed and registered as services |
| Persistence | Boot or Logon Autostart | Registry Run Keys | T1547.001 | RMM service persistence |
| Discovery | Account Discovery | Domain Account | T1087.002 | Domain reconnaissance pre-lateral movement |
| Discovery | Cloud Service Discovery | — | T1526 | S3 bucket identification for exfil staging |
| Credential Access | OS Credential Dumping | NTDS | T1003.003 | NTDS.dit extraction via ntdsutil IFM |
| Credential Access | Brute Force | Credential Stuffing | T1110.004 | LaZagne / Mimikatz / pypykatz usage |
| Defense Evasion | Impair Defenses | Disable or Modify Tools | T1562.001 | Disabled Defender real-time monitoring, added exclusions |
| Lateral Movement | Remote Services | SMB/Windows Admin Shares | T1021.002 | PsExec / Impacket / NetExec via admin shares |
| Lateral Movement | Lateral Tool Transfer | — | T1570 | PsExec / Impacket pushed to additional hosts |
| Exfiltration | Transfer Data to Cloud Account | — | T1537 | s5cmd to attacker-controlled S3; rclone to cloud |
| Impact | Data Encrypted for Impact | — | T1486 | Qilin / DragonForce / Anubis / BERT deployed |

### Kill Chain Phases

- **Actions on Objectives** — credential dumping, data exfiltration, ransomware deployment
- **Installation** — RMM tool persistence as Windows services
- **Command & Control** — MeshCentral / commercial RMM platforms; Cloudflared / ngrok tunnels

---

## 3. Malware & Tools

### Ransomware Families (Storm-2570 Affiliations)

| Family | Notes |
|---|---|
| Qilin | Also tracked in initial_access/checkpoint_vpn_ikev1_auth_bypass_qilin.md |
| DragonForce | Also tracked in command_and_control/dragonforce_teams_turn_relay_c2.md |
| Anubis | Newer RaaS variant; previously less documented |
| BERT | Emerging variant; limited public documentation as of report date |

### Remote Management / Access Tools (Consistent Across Deployments)

- **MeshAgent / MeshCentral** — Primary RMM; MeshCentral is an open-source self-hosted RMM platform. Also detected in command_and_control/meshcentral_agent_masquerading_cloud_services.md.
- **Atera, ScreenConnect, Splashtop, NinjaRMM, Remotely_Agent** — Backup RMM tools; actors deploy multiple to survive partial remediation

### Credential Access Tools

- **Mimikatz** — LSASS memory dumping
- **LaZagne** — Multi-target password recovery (browsers, Windows credentials, databases)
- **pypykatz** — Python Mimikatz port for LSASS parsing
- **ntdsutil** — NTDS.dit extraction via IFM (Install From Media) snapshot (see detection)

### Tunneling / Defense Evasion

- **cloudflared.exe** — Cloudflare Tunnel client; establishes outbound-only encrypted tunnels bypassing inbound firewall rules (see command_and_control/cloudflared_tunnel_rmm_exploitation_persistence.md)
- **ngrok** — Reverse proxy tunnel

### Exfiltration Tools

- **s5cmd** — Amazon S3 CLI utility; used to exfiltrate to attacker-controlled S3 buckets
- **rclone** — Cloud sync tool; configured for attacker-controlled storage endpoints

---

## 4. Threat Actor Profile

| Field | Detail |
|---|---|
| Actor | Storm-2570 |
| Tracking origin | April 2025 (Microsoft) |
| Classification | Ransomware affiliate; financially motivated |
| Ecosystem | Cross-RaaS: Qilin, DragonForce, Anubis, BERT |
| Target sectors | Healthcare, Education, Government, Financial Services, Energy, Retail, IT, Agriculture, Manufacturing, Transportation, NGOs, Chemicals, Commercial Facilities |
| Target geographies | United States, Canada, United Kingdom, Spain, Netherlands, Puerto Rico |
| Distinguishing trait | Consistent toolset across all ransomware affiliations; actor identity separable from payload family |

---

## 5. Splunk Detection Searches

### 5a. Storm-2570 — Multiple RMM Tools Installed Within Short Window

Detects installation of multiple commercial RMM tools as Windows services within a 24-hour window on a single host, consistent with Storm-2570's backup RMM deployment pattern.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Services
    where Services.process_name IN ("MeshAgent.exe","atera_agent.exe","ScreenConnect.exe",
                                     "SplashtopStreamer.exe","ninjarmm-agent.exe","Remotely_Agent.exe")
    by Services.dest Services.process_name Services.service_name Services.start_type
| `drop_dm_object_name(Services)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| stats dc(process_name) as rmm_tool_count values(process_name) as rmm_tools
       min(firstTime) as firstTime max(lastTime) as lastTime by dest
| where rmm_tool_count >= 2
| eval risk_score=case(rmm_tool_count >= 3, 90, rmm_tool_count == 2, 70, true(), 50)
| table firstTime lastTime dest rmm_tools rmm_tool_count risk_score
```

### 5b. Storm-2570 — ntdsutil NTDS.dit IFM Extraction

Detects ntdsutil executing with IFM (Install From Media) arguments for NTDS.dit extraction, consistent with Storm-2570 T1003.003 usage and other ransomware-affiliated actors.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name="ntdsutil.exe"
      AND (Processes.process IN ("*ifm*","*create full*","*ac i ntds*"))
    by Processes.dest Processes.user Processes.parent_process_name
       Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process,"(?i)create full"), 95,
    match(process,"(?i)ifm"), 90,
    true(), 80
)
| where risk_score >= 80
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score count
```

### 5c. Storm-2570 — s5cmd / Rclone Cloud Exfiltration

Detects s5cmd or rclone executing with arguments consistent with bulk data exfiltration to cloud storage, consistent with Storm-2570's exfiltration tradecraft.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("s5cmd.exe","rclone.exe")
    by Processes.dest Processes.user Processes.parent_process_name
       Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process,"(?i)sync|cp|mv") AND match(process,"(?i)s3://|r2://|b2://"), 90,
    process_name="rclone.exe" AND match(process,"(?i)copy|sync"), 85,
    true(), 70
)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score count
```

---

## 6. Risk Scoring

| Component | Score | Rationale |
|---|---|---|
| ntdsutil with IFM arguments | 90–95 | Near-certain NTDS.dit credential dump |
| 3+ RMM tools installed within 24h | 90 | Strong indicator of post-compromise backup persistence |
| 2 RMM tools installed within 24h | 70 | Suspicious; warrants investigation |
| s5cmd/rclone with S3 sync arguments | 85–90 | High-confidence data exfiltration |
| Cloudflared + active RMM on same host | 90 | Defense evasion + remote access combination |

Composite (ntdsutil IFM + 2+ RMMs + rclone on same host within 4 hours) = **Critical (95+)**.

---

## References

- [Microsoft Security Blog — Beyond the Ransomware: Tracking Storm-2570's Consistent Tradecraft Across Deployments (September 24, 2026)](https://www.microsoft.com/en-us/security/blog/2026/09/24/beyond-ransomware-tracking-storm-2570-consistent-tradecraft-across-deployments/)
- [MITRE ATT&CK — T1003.003: OS Credential Dumping: NTDS](https://attack.mitre.org/techniques/T1003/003/)
- [MITRE ATT&CK — T1537: Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/)
- [MITRE ATT&CK — T1562.001: Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
- [MITRE ATT&CK — T1486: Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
