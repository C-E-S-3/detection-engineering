---
scraped_at: 2026-06-08T00:00:00Z
source_url: https://www.proofpoint.com/us/blog/threat-insight/ta4922-suspected-chinese-crime-group-going-global
report_type: threat-intel
severity: high
title: "TA4922: Chinese Cybercrime Actor Expands to Europe and Africa with Atlas RAT, RomulusLoader, SilentRunLoader"
---

# TA4922: Chinese Cybercrime Actor Expands to Europe and Africa with Atlas RAT, RomulusLoader, SilentRunLoader

On June 5, 2026, Proofpoint published a detailed threat research report on TA4922, a Chinese-speaking financially motivated cybercrime actor that has dramatically expanded its geographic targeting and malware arsenal. Previously focused on Japan and East Asia, the group shifted to Germany, Italy, the United Kingdom, and South Africa in early 2026 while deploying three previously undocumented malware families. Proofpoint assesses TA4922 now conducts more unique campaigns than any other tracked cybercrime actor in their telemetry.

## 1. IOCs

### IP Addresses (C2 Infrastructure)

| Indicator | Context |
|-----------|---------|
| 206.238.115.58 | Atlas RAT C2 server; TCP port 886; confirmed active in March 2026 HR-themed campaign |
| 154.211.86.110 | TA4922 C2 infrastructure; associated with Atlas RAT / RomulusLoader campaigns |
| 43.156.77.97 | TA4922 C2 infrastructure; associated with later-stage payload delivery |
| 103.214.172.33 | TA4922 C2 infrastructure; associated with SilentRunLoader credential exfiltration |

### Domains

No domains were explicitly disclosed in public reporting. TA4922 leverages file-sharing platforms (GoFile, MediaFire, LimeWire) for payload staging rather than attacker-registered domains.

### File Hashes

Specific file hashes were not disclosed in public secondary reporting. The Proofpoint full report (paywall/portal) contains SHA256 hashes for Atlas RAT, RomulusLoader, and SilentRunLoader samples.

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1566.001 | Phishing: Spearphishing Attachment | HR-themed and invoice-themed phishing emails containing ZIP archives as attachments |
| Initial Access | T1566.002 | Phishing: Spearphishing Link | ZIP payloads hosted on GoFile, MediaFire, and LimeWire; link delivered in email body |
| Execution | T1204.002 | User Execution: Malicious File | Victim opens ZIP archive and executes the contents, triggering DLL sideloading chain |
| Defense Evasion | T1574.002 | Hijack Execution Flow: DLL Side-Loading | Atlas RAT delivered by placing malicious DLL in same directory as a signed/legitimate binary; DLL loaded automatically on binary execution |
| Persistence | T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | Persistence established for Atlas RAT via registry Run key or scheduled task post-install |
| Collection | T1056.001 | Input Capture: Keylogging | Atlas RAT built-in keylogger captures all user keystrokes |
| Collection | T1113 | Screen Capture | Atlas RAT captures screenshots of the victim desktop on operator command |
| Collection | T1125 | Video Capture | Atlas RAT activates webcam and records video on operator command |
| Credential Access | T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | SilentRunLoader extracts Chrome-stored credentials (passwords, cookies) and exfiltrates to actor-controlled C2 |
| Command and Control | T1571 | Non-Standard Port | Atlas RAT communicates with C2 206.238.115.58 over TCP port 886 — highly anomalous port for legitimate traffic |
| Resource Development | T1587.001 | Develop Capabilities: Malware | Proofpoint assessed with high confidence that TA4922 uses AI coding tools to rapidly develop new Python-based malware; SilentRunLoader retains placeholder strings such as "your_secret_key_here" indicating minimal post-generation review |

## 3. Malware & Tools

| Malware | Type | Platform | Key Capabilities | Notes |
|---------|------|----------|-----------------|-------|
| Atlas RAT (AtlasCross RAT) | Full-featured RAT | Windows | Keylogging, screen capture, webcam recording, file management (read/write/delete), remote shell, process management, remote command execution | First identified in this campaign context by Proofpoint June 2026; C2 TCP port 886; delivered via DLL sideloading from HR-themed ZIP archives |
| RomulusLoader | Malware Loader | Windows | Downloads and executes additional payloads using process hollowing, shellcode injection, and direct execution | First observed in TA4922 campaigns March 23, 2026; targets Japan, later Europe; also delivers legitimate remote monitoring tools (AnyDesk, SyncFuture) in mid-April campaigns |
| SilentRunLoader | Credential Stealer + Loader | Windows | Harvests Chrome-stored credentials (passwords, cookies), exfiltrates to C2; AI-generated code with residual placeholder strings | Deployed against UK targets April 2026 using fake tax authority email lures; Python-based; high confidence AI-assisted development |
| ValleyRAT (Winos 4.0) | RAT | Windows | Remote access, persistence, data collection | Pre-existing TA4922 tool; continued use alongside new arsenal |

## 4. Threat Actor / Campaign Attribution

**Threat Actor:** TA4922 (Proofpoint designation)

- **Category:** Chinese-speaking cybercrime actor; financially motivated
- **Active Since:** At least spring 2025
- **Prior Targeting:** Japan and East Asia (initial access broker activity, fraud, data theft)
- **2026 Expansion:** Germany, Italy, United Kingdom, South Africa
- **Operational Tempo:** Proofpoint identifies TA4922 as the most prolific tracked cybercrime actor by unique campaign count as of mid-2026
- **AI Development:** High-confidence assessment that the group uses AI coding tools to rapidly prototype Python-based malware loaders, with code artifacts (placeholder strings) confirming minimal human review

### Campaign Timeline

| Date | Campaign | Targets | Payload |
|------|----------|---------|---------|
| March 6, 2026 | HR-themed phishing (ZIP on GoFile) | East Asia / Japan | Atlas RAT |
| March 23, 2026 | Corporate/HR lures (first RomulusLoader) | Japan | RomulusLoader |
| April 2, 2026 | HR lures ("Paperwork.zip") | UK, Germany | Atlas RAT |
| April 7, 2026 | Invoice-related lures | UK, Germany, Italy | Atlas RAT / RomulusLoader |
| April 10, 2026 | Fake tax authority emails | UK | SilentRunLoader |
| Mid-April 2026 | RomulusLoader deploying RMM tools | UK, Europe | RomulusLoader → AnyDesk, SyncFuture |
| April–May 2026 | South Africa expansion | South Africa | Multiple payloads |

## 5. Splunk Detection Searches

```spl
-- Detect Atlas RAT C2 beacon: outbound TCP connections to port 886 (anomalous port)
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_port=886
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.bytes_out All_Traffic.bytes_in
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src dest dest_port bytes_out bytes_in risk_score
```

```spl
-- Detect TA4922 known C2 IP connections (Atlas RAT, RomulusLoader, SilentRunLoader)
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest IN ("206.238.115.58","154.211.86.110","43.156.77.97","103.214.172.33")
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src dest dest_port app risk_score
```

```spl
-- Detect execution of unsigned binaries from user-writable paths consistent with HR-ZIP DLL sideloading
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_path="*\\Downloads\\*" OR Processes.process_path="*\\AppData\\Local\\Temp\\*"
    OR Processes.process_path="*\\AppData\\Roaming\\*")
    AND (Processes.process_name="*.exe")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
     Processes.process Processes.process_path Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_path,"(?i)Downloads"), 60,
    match(process_path,"(?i)AppData"), 55,
    1=1, 50)
| where risk_score >= 50
| table firstTime lastTime dest user parent_process_name process_name process_path risk_score
```

## 6. Executive Summary

Proofpoint released research on June 5, 2026 exposing TA4922, a Chinese-speaking cybercrime actor that has pivoted from East Asian targeting to a broad European and African footprint. The group delivers Atlas RAT (a full-featured backdoor capable of keylogging, screen capture, webcam access, and remote command execution) via HR-themed and invoice-lure phishing emails that use ZIP archives hosted on legitimate file-sharing platforms. DLL sideloading enables the payload to run as part of a signed-binary execution context, reducing sandbox and AV trigger rates.

Three previously undocumented malware families were identified: **Atlas RAT** (C2 on non-standard TCP port 886), **RomulusLoader** (process hollowing / shellcode injection loader), and **SilentRunLoader** (Python-based Chrome credential stealer). Proofpoint assessed with high confidence that TA4922 uses generative AI coding tools to accelerate malware development, a trend consistent with GTIG's AI Threat Tracker findings for the first half of 2026. The group's unusually high campaign frequency and rapid tooling evolution make it a priority tracking target for organizations in Europe, Japan, and South Africa across finance, HR, and legal sectors.

**Priority action:** Block or alert on TCP port 886 outbound; ingest TA4922 C2 IPs (206.238.115.58, 154.211.86.110, 43.156.77.97, 103.214.172.33) into firewall/proxy blocklists; flag execution of binaries from user Download and Temp paths.

## References

- [Proofpoint — TA4922: The Suspected Chinese Crime Group is Going Global (2026-06-05)](https://www.proofpoint.com/us/blog/threat-insight/ta4922-suspected-chinese-crime-group-going-global)
- [BleepingComputer — Chinese hackers use new Atlas RAT malware in European cyberattacks](https://www.bleepingcomputer.com/news/security/chinese-hackers-use-new-atlas-rat-malware-in-european-cyberattacks/)
- [The Hacker News — China-Linked TA4922 Expands Phishing Attacks to UK, Germany, Italy, and South Africa](https://thehackernews.com/2026/06/china-linked-ta4922-expands-phishing.html)
- [SecurityWeek — Chinese Cybercrime Group in Spotlight for Record Campaign Pace](https://www.securityweek.com/chinese-cybercrime-group-ta4922-in-spotlight-for-record-campaign-pace/)
