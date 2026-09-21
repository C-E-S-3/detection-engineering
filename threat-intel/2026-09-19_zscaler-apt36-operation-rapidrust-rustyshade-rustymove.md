---
title: "APT36 (Transparent Tribe) Operation RapidRust — RUSTYSHADE GitHub C2 Backdoor, RUSTYMOVE USB Air-Gap Spreading, PSNATCH/BASHNATCH File Stealers"
source: Zscaler ThreatLabz
source_url: https://www.zscaler.com/blogs/security-research/operation-rapidrust-apt36-deploys-rustyshade-rustymove-psnatch-and-bashnatch
date: 2026-09-19
scraped_at: 2026-09-21T00:00:00Z
report_type: threat-intel
severity: high
tags: [apt36, transparent-tribe, operation-rapidrust, rustyshade, rustymove, psnatch, bashnatch, rust-backdoor, github-c2, usb-spreading, air-gap, india, afghanistan, government, defense]
mitre_tactics: [TA0001, TA0005, TA0007, TA0008, TA0009, TA0010, TA0011]
---

# APT36 (Transparent Tribe) Operation RapidRust — RUSTYSHADE GitHub C2 Backdoor, RUSTYMOVE USB Air-Gap Spreading, PSNATCH/BASHNATCH File Stealers

## Executive Summary

Zscaler ThreatLabz published research on September 19, 2026 documenting **Operation RapidRust**, a campaign by the Pakistan-nexus threat actor **APT36** (also known as **Transparent Tribe**, G0134) targeting government and defense organizations in **India** and **Afghanistan**. Activity was observed primarily between August 20 and September 1, 2026.

The campaign deploys four new tools: **RUSTYSHADE**, a 64-bit Rust backdoor that uses attacker-controlled **private GitHub repositories** for command-and-control via the GitHub REST API with AES-256-GCM encrypted communications; **RUSTYMOVE**, a Rust-based Windows tool that continuously searches for and copies pre-staged malware to removable media (USB/SD/MMC) to propagate into air-gapped networks; **PSNATCH**, a Windows file stealer; and **BASHNATCH**, a Linux file stealer. APT36 staged payloads on **Backblaze** cloud storage and registered **typosquatted domains impersonating Indian news outlets** to deliver initial malicious PowerShell scripts.

Operator activity was limited to weekdays between **04:00–11:00 UTC** (09:00–16:00 PKT), consistent with Pakistan working hours.

The full IOC set (1,609+ indicators including file hashes and infrastructure domains) is available in the Zscaler ThreatLabz report. Specific hash/domain values were not reproduced in secondary reporting and are not included here; see the primary source for the full indicator set.

**See also:** `detections/command_and_control/matryoshka_github_private_repo_c2.md` (covers GitHub private repo C2 technique also used by RUSTYSHADE) and `detections/lateral_movement/apt36_rustymove_usb_removable_media_spreading.md` (RUSTYMOVE-specific detection).

## IOCs

### IP Addresses

No IP addresses confirmed for this campaign in secondary reporting. Full infrastructure in Zscaler ThreatLabz primary report.

### Domains

| Indicator | Role |
|-----------|------|
| Typosquatted Indian news outlet domains (specific values in Zscaler full report) | Initial access — malicious PowerShell script staging |

### File Hashes

Specific SHA256/MD5 hashes not reproduced in secondary reporting. 1,609+ indicators in Zscaler ThreatLabz primary report covering RUSTYSHADE, RUSTYMOVE, PSNATCH, and BASHNATCH payloads.

### Malicious File / Process Names to Hunt

| Indicator | Description |
|-----------|-------------|
| Rust-compiled 64-bit Windows PE | RUSTYSHADE backdoor binary (exact name varies per campaign) |
| Rust-compiled Windows executable continuously scanning removable storage | RUSTYMOVE USB propagation tool |
| `PSNATCH` / psnatch (case-insensitive) | Windows file stealer — look for unusual file staging before exfil |
| `BASHNATCH` | Linux file stealer — look for unusual file staging on Linux hosts |

## TTPs (MITRE ATT&CK)

| Tactic | Technique | ID | Description |
|--------|-----------|----|-------------|
| Initial Access | Phishing: Spearphishing Link | T1566.002 | Typosquatted domains impersonating Indian news outlets deliver malicious PowerShell scripts to targets in Indian and Afghan government/defense |
| Resource Development | Stage Capabilities: Upload Malware | T1608.001 | Payloads staged on Backblaze cloud storage for download post-initial-access |
| Defense Evasion | Obfuscated Files or Information | T1027 | RUSTYSHADE encrypts all C2 communications with AES-256-GCM; Rust compilation adds anti-analysis complexity |
| Discovery | System Information Discovery | T1082 | Post-compromise host reconnaissance including victim profiling (OS, hardware, user info) via RUSTYSHADE |
| Discovery | Network Share Discovery | T1135 | Network-share enumeration post-compromise |
| Discovery | System Network Connections Discovery | T1049 | SMB/RPC/IPC$ connectivity probes for lateral movement staging |
| Discovery | System Location Discovery | T1614 | Public-IP geolocation to confirm victim network identity |
| Command and Control | Web Service: Dead Drop Resolver | T1102.001 | RUSTYSHADE polls attacker-controlled **private GitHub repositories** via GitHub REST API; commands delivered as `command.txt`; results exfiltrated via `results.txt` and additional repo files |
| Collection | Data from Local System | T1005 | PSNATCH (Windows) and BASHNATCH (Linux) collect files from local file systems for exfiltration |
| Collection | Screen Capture | T1113 | RUSTYSHADE supports screenshot capture |
| Collection | Video Capture | T1125 | RUSTYSHADE supports webcam collection |
| Lateral Movement | Replication Through Removable Media | T1091 | RUSTYMOVE continuously scans for attached removable storage (USB drives, SD cards, MMC devices); copies pre-staged malicious files to all detected media to reach air-gapped networks |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | RUSTYSHADE exfiltrates staged files via GitHub repository write operations (AES-256-GCM encrypted) |

### Kill Chain Phase

**Delivery → Exploitation → Installation → Command & Control → Actions on Objectives**

## Malware & Tools

| Name | Type | Description |
|------|------|-------------|
| RUSTYSHADE | Windows backdoor (Rust) | 64-bit Rust backdoor; uses attacker-controlled private GitHub repos via REST API as C2 dead drop (command.txt / results.txt); AES-256-GCM encrypted C2; supports victim profiling, heartbeat, screenshot, webcam capture, encrypted file exfiltration |
| RUSTYMOVE | USB air-gap spreading tool (Rust) | Rust-based Windows post-compromise tool; continuously scans for removable storage (USB, SD card, MMC); copies pre-staged malicious files to detected media to propagate into air-gapped networks |
| PSNATCH | Windows file stealer | Collects files from Windows file systems for staging and exfiltration |
| BASHNATCH | Linux file stealer | Collects files from Linux file systems for staging and exfiltration |

## Threat Actor / Campaign Attribution

- **Threat Actor**: APT36 (also known as Transparent Tribe, Mythic Leopard, ProjectM, G0134)
- **Nexus**: Pakistan
- **Motivation**: Espionage — targeting government and defense organizations for intelligence collection
- **Targeting**: Indian and Afghan government agencies, defense organizations, military entities
- **Campaign period**: August 20 – September 1, 2026 (observed activity)
- **Operator hours**: Weekdays only, 04:00–11:00 UTC (09:00–16:00 Pakistan Standard Time)
- **Disclosure**: September 19, 2026 (Zscaler ThreatLabz)
- **Novel TTPs**:
  - New Rust-based toolchain (RUSTYSHADE, RUSTYMOVE) representing a significant upgrade from prior Python/C/C++ tools
  - GitHub private repository C2 — previously seen in Matryoshka (HollowFrame) and APT36's own HACKERAI (GitHub Gist); RUSTYSHADE extends this to private repo two-way communication with AES-256-GCM
  - RUSTYMOVE air-gap propagation mechanism is a significant operational capability upgrade indicating targeting of networks isolated from internet access

## Associated Threat Actors

| Actor | Alias | References |
|-------|-------|------------|
| APT36 | Transparent Tribe, Mythic Leopard, ProjectM | [MITRE ATT&CK G0134](https://attack.mitre.org/groups/G0134/); [Zscaler: Operation RapidRust (Sep 2026)](https://www.zscaler.com/blogs/security-research/operation-rapidrust-apt36-deploys-rustyshade-rustymove-psnatch-and-bashnatch); [Acronis TRU: PATCHCORD/SHEETCORD/HACKERAI (Aug 2026)](https://www.acronis.com/en-us/blog/posts/tru-apt36-cloud-c2/) |

## Splunk Detection Searches

See `detections/command_and_control/matryoshka_github_private_repo_c2.md` for RUSTYSHADE C2 detection via GitHub private repo API access.
See `detections/lateral_movement/apt36_rustymove_usb_removable_media_spreading.md` for RUSTYMOVE USB air-gap propagation detection.

### 1 — RUSTYSHADE C2: Non-Developer Process GitHub API Access (Network)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where
    (All_Traffic.dest_host="api.github.com" OR All_Traffic.dest_host="raw.githubusercontent.com")
    AND All_Traffic.dest_port=443
  by All_Traffic.src All_Traffic.user All_Traffic.process All_Traffic.dest_host All_Traffic.bytes_out
| `drop_dm_object_name(All_Traffic)`
| search NOT process IN ("git.exe","GitHub Desktop.exe","code.exe","node.exe","npm","python.exe","curl.exe","wget")
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    like(process,"%powershell%") OR like(process,"%cmd%"), 90,
    like(process,"%rust%") OR like(process,"%.exe"), 80,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime src user process dest_host bytes_out risk_score
```

**Risk Score**: 70–90 (High–Critical) — Non-developer process connections to GitHub API; Rust-compiled binary or cmd/PowerShell process accessing api.github.com is a strong RUSTYSHADE indicator.

### 2 — RUSTYMOVE: Executable Files Written to Removable Storage (Endpoint)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.action IN ("created","modified")
    AND Filesystem.file_name IN ("*.exe","*.dll","*.ps1","*.bat","*.lnk","*.vbs","*.hta","*.js","*.wsf","*.com")
  by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| where match(file_path, "^[D-Z]:\\\\")
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    like(file_name,"%.exe") AND match(file_path,"^[D-Z]:\\\\"), 85,
    like(file_name,"%.lnk") AND match(file_path,"^[D-Z]:\\\\"), 80,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user process_name file_name file_path risk_score
```

**Risk Score**: 70–85 (High) — Executable or LNK file creation on non-system drives (D: and above) by arbitrary processes. Tune the drive letter range for your environment.

### 3 — PSNATCH/BASHNATCH: Anomalous File Staging Before Exfiltration (Endpoint)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.action="created"
    AND Filesystem.file_name IN ("*.zip","*.7z","*.tar","*.gz","*.rar","*.tar.gz","*.tar.bz2")
  by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| search NOT process_name IN ("7z.exe","7za.exe","winrar.exe","bsdtar.exe","tar","gzip","backup.exe")
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name IN ("psnatch.exe","bashnatch","psnatch"), 95,
    like(file_path,"%AppData%") OR like(file_path,"%Temp%"), 80,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user process_name file_name file_path risk_score
```

**Risk Score**: 65–95 (High–Critical) — Archive file creation by non-standard processes in user temp/AppData paths; exact name match on `psnatch.exe` or `bashnatch` is Critical.

## References

- [Zscaler ThreatLabz: Operation RapidRust — APT36 Deploys RUSTYSHADE, RUSTYMOVE, PSNATCH, and BASHNATCH](https://www.zscaler.com/blogs/security-research/operation-rapidrust-apt36-deploys-rustyshade-rustymove-psnatch-and-bashnatch)
- [The Hacker News: Transparent Tribe Deploys New Rust Backdoor Using Private GitHub Repositories for C2](https://thehackernews.com/2026/09/transparent-tribe-deploys-new-rust.html)
- [Security Boulevard: Operation RapidRust](https://securityboulevard.com/2026/09/operation-rapidrust-apt36-deploys-rustyshade-rustymove-psnatch-and-bashnatch/)
- [GBHackers: APT36 Targets Indian Government and Defense Organizations With New Rust Malware Arsenal](https://gbhackers.com/apt36-malware-campaign/)
- [MITRE ATT&CK: APT36 (G0134)](https://attack.mitre.org/groups/G0134/)
- [MITRE ATT&CK: T1102.001 — Web Service: Dead Drop Resolver](https://attack.mitre.org/techniques/T1102/001/)
- [MITRE ATT&CK: T1091 — Replication Through Removable Media](https://attack.mitre.org/techniques/T1091/)
- [Prior APT36 tracking: 2026-08-13_acronis-tru-patchcord-sheetcord-hackerai-apt36.md]
