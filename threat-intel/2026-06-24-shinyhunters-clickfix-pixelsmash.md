---
scraped_at: 2026-06-24T00:00:00Z
source_urls:
  - https://www.rapid7.com/blog/post/etr-active-exploitation-of-oracle-peoplesoft-zero-day-cve-2026-35273/
  - https://thehackernews.com/2026/06/shinyhunters-exploits-oracle-peoplesoft.html
  - https://arcticwolf.com/resources/blog/critical-oracle-peoplesoft-vulnerability-actively-exploited-in-shinyhunters-campaign/
  - https://jfrog.com/blog/pixelsmash-critical-ffmpeg-vulnerability-turns-media-files-into-weapons/
  - https://thehackernews.com/2026/06/clickfix-campaigns-expand-malware.html
  - https://attack.mitre.org/techniques/T1204/004/
report_type: threat-intel
severity: critical
title: "2026-06-24: ShinyHunters CVE-2026-35273, FFmpeg PixelSmash CVE-2026-8461, ClickFix T1204.004 Expansion"
---

## Summary

Three high-priority threat intelligence items requiring immediate detection coverage as of 2026-06-24:

1. **CVE-2026-35273** — Oracle PeopleSoft SSRF→RCE actively exploited by ShinyHunters (UNC6240)
2. **CVE-2026-8461 (PixelSmash)** — FFmpeg heap OOB write via crafted media files affecting self-hosted media servers
3. **ClickFix T1204.004 Expansion** — Widespread fake CAPTCHA campaign now delivering multiple payload families including DeepLoad (WMI persistence) and OXLOADER/CastleStealer (via Google Ads)

---

## Threat 1: CVE-2026-35273 — Oracle PeopleSoft PeopleTools SSRF/RCE

### Overview

| Field | Value |
|-------|-------|
| CVE | CVE-2026-35273 |
| CVSS | 9.8 (Critical) |
| CWE | CWE-918 (Server-Side Request Forgery) |
| Vendor | Oracle |
| Product | PeopleSoft Enterprise PeopleTools |
| Exploited By | ShinyHunters (UNC6240) |
| Active Since | May 27, 2026 (zero-day, predating Oracle advisory by 2 weeks) |
| Primary Target | Higher Education institutions |

### Attack Mechanics

The vulnerable endpoints are:
- `/PSEMHUB/hub` — PeopleSoft Enterprise Manager Hub
- `/PSIGW/HttpListeningConnector` — Integration Gateway HTTP connector

Both endpoints are unauthenticated and process HTTP requests that can be manipulated to trigger server-side requests (SSRF), which chain to RCE.

### ShinyHunters (UNC6240) Post-Exploitation TTPs

| Phase | Technique | Observable |
|-------|-----------|-----------|
| Initial Access | T1190 SSRF→RCE via PSEMHUB/PSIGW | HTTP requests to /PSEMHUB/hub, /PSIGW/HttpListeningConnector |
| Persistence | T1219 MeshCentral agent deployment | `meshagent` process, often from /tmp or /var/tmp |
| Lateral Movement | T1021.004 SSH credential stuffing | `[victim]_fanout.sh` script, rapid SSH from single PID |
| Credential Capture | T1187 Forced SMB Authentication | Outbound port 445 to external attacker-controlled SMB server |
| Impact | T1491 Defacement / Marker | `README-IF-YOU-SEE-THIS-YOUVE-BEEN-HACKED.TXT` dropped in PeopleSoft dirs |

### IOCs

| Indicator | Type | Description |
|-----------|------|-------------|
| `/PSEMHUB/hub` | URL path | Primary exploitation endpoint |
| `/PSIGW/HttpListeningConnector` | URL path | SSRF trigger vector |
| `meshagent` | Process name | MeshCentral remote access agent |
| `*_fanout.sh` | Script name | SSH lateral movement script |
| `README-IF-YOU-SEE-THIS-YOUVE-BEEN-HACKED.TXT` | Filename | Compromise marker |
| Port 445 outbound to external IP | Network | NetNTLM hash capture |

### Mitigation

1. Restrict access to `/PSEMHUB/` and `/PSIGW/` endpoints to known PeopleSoft integration IPs only
2. Patch PeopleSoft PeopleTools to latest version (Oracle issued emergency patch)
3. Block outbound SMB (port 445) from application servers at the firewall
4. Hunt for `meshagent` process on all Linux application servers
5. Search for `*_fanout.sh` scripts in /tmp, /var/tmp, /home directories

---

## Threat 2: CVE-2026-8461 (PixelSmash) — FFmpeg MagicYUV Heap OOB Write

### Overview

| Field | Value |
|-------|-------|
| CVE | CVE-2026-8461 |
| Name | PixelSmash |
| CVSS | 8.8 (High) |
| Vendor | FFmpeg Project |
| Component | libavcodec — MagicYUV decoder |
| Discovery | JFrog Security Research |

### Technical Details

The flaw resides in the MagicYUV decoder's handling of subsampled pixel formats (YUV420P and similar). A rounding mismatch between frame allocation and chroma plane computation allows a 50KB crafted AVI/MKV/MOV file to write 640 attacker-controlled bytes past a heap buffer boundary.

### Affected Applications

- **Jellyfin** (confirmed RCE without ASLR)
- **Nextcloud** (confirmed RCE without ASLR)
- **Kodi** — crash confirmed, RCE expected
- **mpv** — crash confirmed
- File manager thumbnail generators (GNOME Files, Dolphin, Thunar)
- Cloud transcoding pipelines using libavcodec

### TTPs

| Technique | ID | Observable |
|-----------|-----|-----------|
| Exploitation for Client Execution | T1203 | FFmpeg SIGSEGV/SIGABRT crash log during media processing |
| Ingress Tool Transfer | T1105 | Shell spawned by ffmpeg post-exploitation |

### Mitigation

1. Update FFmpeg to the patched version (>= 7.1.2 or >= 6.1.3-security)
2. Block upload of AVI/MKV/MOV files in Nextcloud if not required
3. Enable system-level ASLR (`/proc/sys/kernel/randomize_va_space = 2`)
4. Alert on FFmpeg process crashes via systemd journal/coredump monitoring

---

## Threat 3: ClickFix T1204.004 Expansion

### Overview

ClickFix continues to expand as the primary social engineering delivery vector for 2026. MITRE ATT&CK added T1204.004 (Malicious Copy and Paste) in March 2025 to formally classify this technique.

### Current Active Campaigns (June 2026)

| Campaign | Payload | Delivery | Key TTPs |
|----------|---------|----------|----------|
| Fake CAPTCHA / Bot verification | Vidar Stealer, Phexia Stealer | Compromised websites | T1204.004, T1059.001, T1555.003 |
| Fake Claude AI MSI installer | HellsUchecker backdoor | Malicious Google Ads | T1204.004, T1218.007, T1546.003 |
| OXLOADER via Google Ads | CastleStealer | Malvertising | T1218.007, T1555.003 |
| DeepLoad variant | Loader + WMI persistence | Phishing / ClickFix | T1204.004, T1546.003, T1059.001 |
| WhatsApp VBScript delivery | RMM software | Direct message | T1204.001, T1219 |

### MITRE ATT&CK Mapping

| Tactic | Technique | Sub-technique | Description |
|--------|-----------|---------------|-------------|
| Execution | T1204 | T1204.004 | Malicious Copy and Paste (ClickFix core) |
| Execution | T1059 | T1059.001 | PowerShell from clipboard payload |
| Execution | T1218 | T1218.007 | Msiexec (OXLOADER/CastleStealer MSI) |
| Execution | T1218 | T1218.005 | Mshta (HellsUchecker HTA payload) |
| Persistence | T1546 | T1546.003 | WMI Event Subscription (DeepLoad) |
| Persistence | T1547 | T1547.001 | Registry Run Key (Phexia/HellsUchecker) |
| Credential Access | T1555 | T1555.003 | Browser credential theft (CastleStealer, Phexia) |
| Defense Evasion | T1027 | — | Encoded PowerShell payloads |

### Key IOCs

| Indicator | Type | Campaign |
|-----------|------|---------|
| PowerShell with `-WindowStyle Hidden -EncodedCommand` | Command line | ClickFix general |
| `cmd.exe` / `powershell.exe` parent = browser | Process tree | ClickFix general |
| WMI EventFilter/EventConsumer creation | Registry/Event | DeepLoad |
| MSI from Downloads/Temp path via msiexec | Process | OXLOADER/CastleStealer |
| `Login Data` / `logins.json` access by non-browser | File access | CastleStealer, Phexia, Vidar |
| DPAPI MasterKey folder access by non-system process | File access | Browser credential theft |

---

## Detection Rules

Wazuh rules 103448–103473 in `cve-2026-06-24-shinyhunters-clickfix-pixelsmash.xml` provide coverage for:

- **PeopleSoft CVE-2026-35273**: 103448–103457
  - HTTP probe/exploitation of PSEMHUB/PSIGW endpoints
  - MeshCentral agent detection
  - SSH fanout lateral movement script
  - Outbound SMB to external IP
  - Compromise marker file
- **FFmpeg PixelSmash CVE-2026-8461**: 103458–103461
  - FFmpeg SIGSEGV/crash detection
  - Media server context elevation
  - Post-exploitation shell spawn
  - Repeated crash probing
- **ClickFix T1204.004 + OXLOADER/CastleStealer**: 103462–103473
  - PowerShell hidden/encoded from browser parent
  - Browser spawning cmd/powershell
  - Mshta/wscript remote URL execution
  - WMI subscription creation (DeepLoad)
  - Msiexec from temp/download path (OXLOADER)
  - Browser credential database access (CastleStealer)
  - DPAPI MasterKey access by non-system process
  - Fake CAPTCHA URL patterns (Traefik)
  - Registry Run Key with temp path (Phexia/HellsUchecker)
