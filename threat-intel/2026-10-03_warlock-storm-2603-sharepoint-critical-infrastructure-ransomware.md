---
scraped_at: "2026-10-04T00:00:00Z"
source_url: "https://rewterz.com/threat-advisory/sharepoint-0-day-exploited-to-deploy-warlock-ransomware-active-iocs"
report_type: threat-intel
severity: critical
title: "Warlock Ransomware (Storm-2603 / Gold Salem / Longlegs): SharePoint Exploitation Targeting Critical Infrastructure"
---

# Warlock Ransomware (Storm-2603): SharePoint Exploitation Targeting Critical Infrastructure

## 1. IOCs

### IP Addresses

| IP | Role |
|----|------|
| 65.38.121.198 | C2 / infrastructure |
| 131.226.2.6 | C2 / infrastructure |
| 134.199.202.205 | Infrastructure |
| 104.238.159.149 | Infrastructure |
| 188.130.206.168 | Infrastructure |

### Domains

| Domain | Role |
|--------|------|
| update.updatemicfosoft.com | C2 (typosquats Microsoft Update) |
| msupdate.updatemicfosoft.com | C2 (typosquats Microsoft Update) |
| litter.catbox.moe | Payload staging (public file sharing abused) |
| xn8xyt-drop.s3.wasabisys.com | Payload staging (Wasabi S3-compatible object storage) |

### File Hashes

| Hash | Type | Description |
|------|------|-------------|
| 02b4571470d83163d103112f07f1c434 | MD5 | Warlock ransomware component |

### Web Shells

| Filename | Description |
|----------|-------------|
| spinstall0.aspx | ASPX web shell deployed to SharePoint; used for persistent access and C2 relay |
| layout2sp.aspx | ASPX web shell deployed to SharePoint; used for persistent access |

## 2. TTPs

| Tactic | Technique | Detail |
|--------|-----------|--------|
| Initial Access | T1190 – Exploit Public-Facing Application | Exploits Microsoft SharePoint vulnerabilities (CVE-2026-45659, CVE-2026-50522, CVE-2026-56164, and the earlier CVE-2025-53770 "ToolShell" zero-day) |
| Persistence | T1505.003 – Web Shell | Deploys ASPX web shells (spinstall0.aspx, layout2sp.aspx) to SharePoint servers |
| Credential Access | T1003.001 – LSASS Memory | Uses Mimikatz to dump credentials from LSASS memory |
| Lateral Movement | T1021.002 – SMB/Windows Admin Shares | Uses PsExec and Impacket toolkit for lateral movement |
| Defense Evasion | T1068 / BYOVD | Loads vulnerable signed kernel driver to terminate EDR and security tool processes before ransomware execution |
| Impact | T1486 – Data Encrypted for Impact | Warlock ransomware encrypts files post-EDR-kill |

## 3. Malware & Tools

| Tool / Malware | Description |
|----------------|-------------|
| Warlock ransomware | File-encrypting ransomware deployed as final payload after EDR evasion |
| ASPX web shells (spinstall0.aspx, layout2sp.aspx) | ASPX shells planted on SharePoint servers for persistent remote access and lateral staging |
| Mimikatz | Credential dumping from LSASS memory |
| PsExec | Remote process execution for lateral movement |
| Impacket toolkit | SMB/WMI-based lateral movement and remote execution |
| Vulnerable signed driver (BYOVD) | Abused signed kernel driver used to terminate security tools before ransomware launch |

## 4. Threat Actor / Campaign Attribution

| Field | Detail |
|-------|--------|
| Actor aliases | Storm-2603, Gold Salem, Longlegs, Warlock Group |
| Nexus | China-aligned threat actor |
| Active since | March 2025 |
| Targeting | Water utilities, telecommunications providers, regional governments, universities in Portuguese- and Spanish-speaking countries (Europe, Africa, Latin America) |
| Sector | Critical infrastructure — water, telecom, public administration, education |
| Victimology | At least four confirmed victims in Portuguese/Spanish-speaking countries as of October 2026 |

Storm-2603 (tracked by Symantec as Longlegs and by CrowdStrike as Gold Salem) is a China-nexus threat actor that has been active since at least March 2025. The group's primary initial access vector is exploitation of unpatched Microsoft SharePoint servers. Post-exploitation activity follows a consistent playbook: web shell deployment, Mimikatz credential harvest, lateral movement via PsExec/Impacket, BYOVD-based EDR termination, and final ransomware deployment. The BYOVD step (loading a vulnerable but legitimately signed driver to kill security processes) is a signature technique distinguishing Storm-2603 from opportunistic ransomware affiliates.

The group's advisory from Singapore's IMDA targeting the ICM sector confirms the group's focus on sectors critical to national continuity, particularly in developing-world markets with lower enterprise security maturity.

## 5. Splunk Detection Searches

### ASPX Web Shell Deployment on SharePoint (IIS)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_name IN ("spinstall0.aspx","layout2sp.aspx","*.aspx")
    AND Filesystem.file_path IN ("*\\inetpub\\wwwroot\\*","*\\SharePoint\\*","*/inetpub/wwwroot/*")
  by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_name,"(?i)(spinstall0|layout2sp)\.aspx"), 95,
    match(file_path,"(?i)(wwwroot|sharepoint)") AND match(file_name,"\.aspx$"), 80,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime dest user file_name file_path risk_score
```

### Warlock C2 Domains in DNS

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query IN ("update.updatemicfosoft.com","msupdate.updatemicfosoft.com")
  by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95, note="Warlock/Storm-2603 C2 domain"
| table firstTime lastTime src query answer risk_score note
```

### BYOVD: Vulnerable Driver Loading Before Mass Process Termination

See `detections/defense_evasion/byovd_vulnerable_driver_edr_evasion.md` and `detections/defense_evasion/byovd_security_tool_termination.md`.

## 6. Executive Summary

Warlock (Storm-2603 / Gold Salem / Longlegs) is a China-aligned ransomware-deploying threat actor targeting critical infrastructure organizations in Portuguese- and Spanish-speaking countries. The group enters via unpatched Microsoft SharePoint servers, deploys ASPX web shells for persistent access, harvests credentials with Mimikatz, moves laterally with PsExec and Impacket, then terminates EDR/security tools using a bring-your-own-vulnerable-driver (BYOVD) technique before releasing the Warlock encryptor.

Defenders should prioritize patching SharePoint (CVE-2025-53770, CVE-2026-45659, CVE-2026-50522, CVE-2026-56164), auditing IIS/SharePoint for unexpected ASPX files, enabling Controlled Folder Access to restrict unauthorized encryption, and monitoring for BYOVD driver load patterns.

## References

- [Rewterz — SharePoint 0-Day Exploited to Deploy Warlock Ransomware: Active IOCs](https://rewterz.com/threat-advisory/sharepoint-0-day-exploited-to-deploy-warlock-ransomware-active-iocs)
- [Symantec/Broadcom — Warlock Ransomware Targets Water and Telecom Operators](https://www.broadcom.com/support/security-center/protection-bulletin/warlock-ransomware-targets-water-and-telecom-operators)
- [Security.com — Warlock Ransomware Attackers Hit Water and Telecom Operators](https://www.security.com/threat-intelligence/warlock-ransomware-critical-infrastructure)
- [CyberPress — Warlock Attackers Abuse Vulnerable Driver to Disable Security Tools](https://cyberpress.org/warlock-ransomware-sharepoint/)
- [IMDA Singapore — Storm-2603 Advisory (ICM Sector)](https://www.imda.gov.sg/-/media/imda/files/regulations-and-licensing/regulations/advisories/infocomm-media-cyber-security/storm-2603-exploits-sharepoint-vulnerabilities-to-deliver-backdoor-and-warlock-ransomware.pdf)
- [DailySecurityReview — Warlock Group / GOLD SALEM Threat Profile](https://dailysecurityreview.com/resources/threat-actors-resources/warlock-group-gold-salem-aka-storm-2603-threat-profile/)
- [Microsoft — Disrupting Active Exploitation of On-Premises SharePoint Vulnerabilities](https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities/)
- [MITRE ATT&CK — T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1505.003 Web Shell](https://attack.mitre.org/techniques/T1505/003/)
