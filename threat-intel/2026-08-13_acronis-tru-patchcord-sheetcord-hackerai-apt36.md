---
title: "APT36 (Transparent Tribe) New Malware Cluster: PATCHCORD, SHEETCORD, HACKERAI"
date: 2026-08-13
scraped_at: 2026-08-15T00:00:00Z
source_url: https://www.acronis.com/en/tru/posts/patchcord-new-malware-cluster-targets-afghan-telecom-and-south-asian-critical-infrastructure/
severity: high
tags:
  - apt36
  - transparent-tribe
  - patchcord
  - sheetcord
  - hackerai
  - pakistan-nexus
  - south-asia
  - telecom
  - c2
---

# APT36 (Transparent Tribe) New Malware Cluster: PATCHCORD, SHEETCORD, HACKERAI

## Executive Summary

Acronis Threat Research Unit (TRU) published analysis on August 13, 2026 of a new three-implant cluster attributed to APT36 (Transparent Tribe, G0134), a Pakistan-nexus threat actor. The cluster — comprising PATCHCORD (C/C++ HTTP backdoor), SHEETCORD (Go-based Google Sheets API C2), and HACKERAI (Go-based GitHub Gist C2 with browser shortcut hijacking) — targets Afghan telecom operators and South Asian critical infrastructure. Activity was observed from at least March 2026. A centralized C2 server at 46.30.188[.]13 hosts a SuperShell webshell manager and all three implants communicate through it or via cloud-service dead-drop channels.

## IOCs

### Domains

| Indicator | Type | Context |
|-----------|------|---------|
| `appstoore[.]solutions` | C2 Domain | PATCHCORD hard-coded C2; maps to 46.30.188.13:8080; impersonates app store |
| `nic-support[.]site` | Delivery Domain | SHEETCORD delivery; impersonates India NIC; "Ministry of Defense Employee Breach Update" lure |

### IPs

| Indicator | Type | Context |
|-----------|------|---------|
| `46.30.188[.]13` | C2 IP | Central C2 server; TCP port 8080; hosts SuperShell webshell manager; used by all three implants |

## TTPs

| Technique | ID | Description |
|-----------|-----|-------------|
| Application Layer Protocol: Web Protocols | T1071.001 | PATCHCORD uses HTTP to appstoore[.]solutions:8080 for C2 |
| Web Service: Bidirectional Communication | T1102.002 | SHEETCORD uses Google Sheets API as bidirectional C2 channel |
| Web Service: Dead Drop Resolvers | T1102.001 | HACKERAI uses GitHub Gists for command retrieval |
| Phishing: Spearphishing Link | T1566.002 | Delivery via nic-support[.]site impersonating Indian NIC portal |
| User Execution: Malicious File | T1204.002 | Afghan Telecom TMS installer trojanized with PATCHCORD |
| Shortcut Modification | T1547.009 | HACKERAI hijacks browser LNK shortcuts (Chrome, Edge, Firefox, Brave) for persistence |
| Obfuscated Files or Information | T1027 | HACKERAI double-XOR encoding; hardcoded GitHub PAT |

## Malware / Tools

### PATCHCORD
- **Language:** C/C++
- **Delivery:** Trojanized Afghan Telecom TMS (Traffic Management System) installer
- **C2:** HTTP to appstoore[.]solutions:8080 (→ 46.30.188[.]13)
- **Capabilities:** Backdoor; remote command execution via hard-coded C2

### SHEETCORD
- **Language:** Go
- **Delivery:** nic-support[.]site — fake Indian NIC portal with "Ministry of Defense Employee Breach Update" lure document
- **C2:** Google Sheets API (bidirectional — reads commands from cells, writes output to cells)
- **Capabilities:** Backdoor; uses legitimate cloud service to blend C2 traffic with normal traffic

### HACKERAI
- **Language:** Go
- **C2:** GitHub Gist API (reads commands from Gist content)
- **Persistence:** Hijacks browser LNK shortcuts (Chrome, Edge, Firefox, Brave) to execute HACKERAI on browser launch
- **Evasion:** Double-XOR encoding; hardcoded GitHub Personal Access Token (PAT)
- **Note:** AI-assisted development artifacts visible in code (leftover test code, structural patterns suggesting LLM-assisted authorship)

## Attribution

- **Threat Actor:** APT36 / Transparent Tribe (MITRE G0134)
- **Nexus:** Pakistan
- **Targeting:** Afghan telecom operators; South Asian critical infrastructure (India, Pakistan region)
- **Active since (this cluster):** March 2026
- **Infrastructure:** Central C2 at 46.30.188[.]13 with SuperShell webshell manager

## Splunk Detection Queries

### Query 1: DNS IOC — PATCHCORD/SHEETCORD C2 and Delivery Domains

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query IN ("appstoore.solutions", "nic-support.site")
by DNS.src DNS.query DNS.record_type
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src query record_type risk_score
```

### Query 2: Behavioral — Non-Browser Process Connecting to Google Sheets API (SHEETCORD)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_dns="sheets.googleapis.com"
  AND All_Traffic.process_name NOT IN (
    "chrome.exe","firefox.exe","msedge.exe","iexplore.exe","safari","opera.exe",
    "brave.exe","vivaldi.exe","WINWORD.exe","EXCEL.EXE","OUTLOOK.EXE",
    "Sheets.exe","googledrivesync.exe","GoogleDriveFS.exe","python.exe","node.exe","java"
  )
by All_Traffic.src All_Traffic.dest_dns All_Traffic.process_name All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name, "(?i)mshta|wscript|cscript|powershell|rundll32|regsvr32"), 90,
    match(process_name, "(?i)svchost|services"), 75,
    1=1, 55)
| where risk_score >= 55
| table firstTime lastTime src dest_dns process_name dest_port risk_score
```

### Query 3: Behavioral — Non-Developer Process Connecting to GitHub Gist API (HACKERAI)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where (All_Traffic.dest_dns="gist.github.com" OR All_Traffic.dest_dns="api.github.com")
  AND All_Traffic.process_name NOT IN (
    "chrome.exe","firefox.exe","msedge.exe","git.exe","gh.exe","code.exe",
    "node.exe","python.exe","java","go.exe","curl.exe","wget.exe"
  )
by All_Traffic.src All_Traffic.dest_dns All_Traffic.process_name All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name, "(?i)mshta|wscript|cscript|powershell|rundll32|regsvr32"), 90,
    match(process_name, "(?i)svchost|services"), 80,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime src dest_dns process_name dest_port risk_score
```

## References

- [Acronis TRU — PATCHCORD Cluster (2026-08-13)](https://www.acronis.com/en/tru/posts/patchcord-new-malware-cluster-targets-afghan-telecom-and-south-asian-critical-infrastructure/)
- [MITRE ATT&CK G0134 — APT36](https://attack.mitre.org/groups/G0134/)
- [MITRE ATT&CK T1102.002 — Web Service: Bidirectional Communication](https://attack.mitre.org/techniques/T1102/002/)
- [MITRE ATT&CK T1102.001 — Web Service: Dead Drop Resolvers](https://attack.mitre.org/techniques/T1102/001/)
- [MITRE ATT&CK T1071.001 — Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
