---
title: "Gunra (Golden Community) Ransomware — CISA Joint Advisory AA26-222A"
date: 2026-08-10
scraped_at: 2026-08-15T00:00:00Z
source_url: https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-222a
severity: high
tags:
  - gunra
  - golden-community
  - ransomware
  - conti
  - fortinet
  - cve-2024-55591
  - cve-2025-24472
  - cisa
---

# Gunra (Golden Community) Ransomware — CISA Joint Advisory AA26-222A

## Executive Summary

CISA, FBI, NSA, USSS, DC3, and South Korean KNPA issued a joint advisory on August 10, 2026 regarding Gunra ransomware (operated by the Golden Community group). Gunra is a Conti-derived RaaS (Ransomware-as-a-Service) that has been active since April 2025, launching as a formal RaaS operation in January 2026. The group exploits Fortinet FortiOS/FortiProxy authentication bypass vulnerabilities (CVE-2024-55591 and CVE-2025-24472) for initial access, establishes persistent tunnels via OpenSSH, and performs double-extortion — exfiltrating data to OneDrive/SharePoint via `main.exe` before deploying ChaCha20+RSA-4096 encryption that appends the `.ENCRT` extension. The Linux variant contains a cryptographic flaw allowing free file recovery. The South Korean KNPA co-signing this advisory suggests significant targeting overlap with DPRK-adjacent patterns.

## IOCs

### File Hashes

| Indicator | Type | Context |
|-----------|------|---------|
| `854e5f77f788bbbe6e224195e115c749172cd12302afca370d4f9e3d53d005fd` | SHA256 | Gunra Windows encryptor binary; ChaCha20+RSA-4096; appends .ENCRT; drops R3ADM3.txt |

### Domains

| Indicator | Type | Context |
|-----------|------|---------|
| `datapub[.]news` | Leak Site | Gunra dedicated leak site clearnet mirror; may redirect to Tor DLS |

## TTPs

| Technique | ID | Description |
|-----------|-----|-------------|
| Exploit Public-Facing Application | T1190 | CVE-2024-55591 + CVE-2025-24472 FortiOS/FortiProxy auth bypass for initial access |
| Data Encrypted for Impact | T1486 | ChaCha20+RSA-4096 encryption; .ENCRT extension; R3ADM3.txt ransom note |
| Exfiltration to Cloud Storage | T1567.002 | `main.exe` exfiltrates to OneDrive/SharePoint before encryption (double-extortion) |
| Remote Services: SSH | T1021.004 | OpenSSH persistent tunneling for lateral movement and persistence |
| Remote Services: RDP | T1021.001 | RDP lateral movement post-initial access |
| Remote Services: SMB | T1021.002 | SMB lateral movement post-initial access |
| Inhibit System Recovery | T1490 | Consistent with Conti-derived ransomware playbook |

## Malware / Tools

### Gunra Windows Encryptor
- **Hash:** `854e5f77f788bbbe6e224195e115c749172cd12302afca370d4f9e3d53d005fd` (SHA256)
- **Encryption:** ChaCha20 + RSA-4096 multithreaded encryption
- **Traversal:** Drives A–Z systematic traversal
- **Extension:** `.ENCRT` appended to all encrypted files
- **Ransom Note:** `R3ADM3.txt` dropped in directories
- **Platform:** Windows

### Gunra Linux Variant
- Cryptographic flaw allows free file recovery (key material can be recovered without paying ransom)
- Platform: Linux

### main.exe
- Pre-encryption exfiltration tool used in double-extortion
- Targets: OneDrive, SharePoint (Microsoft cloud storage)
- Executed before encryption phase to maximize leverage

## Attribution

- **Threat Actor:** Golden Community (Gunra ransomware operators)
- **RaaS Lineage:** Conti-derived
- **Active:** April 2025 (first observed); January 2026 (formal RaaS launch)
- **Advisory:** CISA AA26-222A (co-signed by FBI, NSA, USSS, DC3, KNPA)
- **Targeting:** Global; South Korean KNPA co-signing indicates significant regional targeting

## Splunk Detection Queries

### Query 1: High-Confidence — .ENCRT File Extension and R3ADM3.txt Ransom Note Creation

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_name="R3ADM3.txt"
   OR match(Filesystem.file_path, "(?i)\.ENCRT$")
by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.action
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| table firstTime lastTime dest user file_name file_path action risk_score
```

### Query 2: CVE-2024-55591 / CVE-2025-24472 — Fortinet API Exploitation via WebSocket/Node.js UA

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Web.Web
where Web.url IN ("*/api/v2/cmdb/system/admin*", "*/jsconsole*", "*node.cgi*")
  AND Web.http_method IN ("PUT","POST")
  AND Web.http_user_agent IN ("Node.js*","*websocket*")
  AND Web.status IN ("200","201","204")
by Web.src Web.dest Web.url Web.http_method Web.http_user_agent Web.status Web.user
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src dest url http_method http_user_agent status user risk_score
```

### Query 3: Pre-Encryption Exfiltration — main.exe to OneDrive/SharePoint (>10 MB)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where (All_Traffic.dest_dns="*.sharepoint.com" OR All_Traffic.dest_dns="*.onedrive.com")
  AND All_Traffic.bytes_out > 10000000
  AND All_Traffic.process_name NOT IN ("WINWORD.exe","EXCEL.EXE","OneDrive.exe","Teams.exe","chrome.exe","firefox.exe","msedge.exe")
by All_Traffic.src All_Traffic.dest_dns All_Traffic.process_name All_Traffic.bytes_out
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| table firstTime lastTime src dest_dns process_name bytes_out risk_score
```

## References

- [CISA Advisory AA26-222A — Gunra Ransomware (2026-08-10)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-222a)
- [MITRE ATT&CK T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK T1486 — Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK T1567.002 — Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002/)
- [CVE-2024-55591 — Fortinet FortiOS/FortiProxy Auth Bypass](https://nvd.nist.gov/vuln/detail/CVE-2024-55591)
- [CVE-2025-24472 — Fortinet FortiOS/FortiProxy Auth Bypass](https://nvd.nist.gov/vuln/detail/CVE-2025-24472)
