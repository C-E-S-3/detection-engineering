---
scraped_at: "2026-10-14T00:00:00Z"
source_url: "https://blog.talosintelligence.com/break-the-silence-kazakhstan-nexus-uat-6275-targets-cis-government-organizations/"
report_type: threat-intel
severity: high
title: "Talos October 14 2026: UAT-6275 — Kazakhstan-Nexus APT Targeting CIS Government Organizations with Chvost, Laplas, and PickleShell Implants"
---

## 1. IOCs

### Domains

No domains published at time of report. Full IOC list maintained by Talos at:
https://github.com/Cisco-Talos/IOCs/tree/main/2026/10/UAT-6275

### IPs

No IPs published in secondary reporting at time of scrape.

### Hashes

No hashes published in secondary reporting at time of scrape. Refer to Talos GitHub IOC repository for full artifact list.

### Behavioral Indicators

| Indicator | Context |
|-----------|---------|
| PS2EXE-compiled PowerShell droppers distributed via GitHub raw URLs | UAT-6275 stages PowerShell payloads on GitHub and compiles them to EXEs using PS2EXE to evade script-based detections |
| WinRAR archive exploiting CVE-2025-8088 delivering malicious DLL | Initial access via emailed or web-delivered ZIP archives triggering WinRAR ACE exploit before user opens content |
| Macro-laden DOCX files with embedded OLE objects | Phishing delivery of weaponized Office documents targeting CIS government staff |
| Reverse shells beaconing to operator-controlled infrastructure | Chvost, Laplas, and PickleShell reverse-shell implants establish C2 post-exploitation |

---

## 2. TTPs

| MITRE Technique | ID | Description |
|----------------|-----|-------------|
| Spearphishing Attachment | T1566.001 | Macro-laden Word documents delivered via targeted email to CIS government personnel |
| Exploit Public-Facing Application | T1190 | WinRAR CVE-2025-8088 used for client-side exploitation during archive extraction |
| Command and Scripting Interpreter: PowerShell | T1059.001 | PS2EXE-compiled PowerShell droppers used to deploy implants, evading script-only detections |
| Ingress Tool Transfer | T1105 | GitHub raw URLs used for second-stage payload staging and download |
| Web Service: Dead Drop Resolver | T1102.001 | GitHub repositories used to host and rotate C2 staging payloads |
| Remote Access Software | T1219 | Chvost, Laplas, and PickleShell provide interactive reverse-shell C2 sessions |
| System Information Discovery | T1082 | ipconfig, whoami, net.exe used for post-exploitation enumeration |
| Screen Capture | T1113 | Screenshot collection observed as part of collection phase |
| Archive Collected Data | T1560 | Data compressed before exfiltration |

---

## 3. Malware & Tools

| Name | Type | Notes |
|------|------|-------|
| Chvost | Reverse shell implant | Custom-developed; lightweight persistent reverse shell; name is Russian for "tail" |
| Laplas | Reverse shell implant | Second custom implant; observed alongside Chvost in multi-implant deployments |
| PickleShell | Reverse shell implant | Third implant in the trio; Python-serialization–style naming convention |
| PS2EXE | Compiler tool | Open-source PowerShell-to-EXE converter; abused to bypass PS Script Block Logging |
| WinRAR (CVE-2025-8088) | Exploit vehicle | Weaponized archive exploiting unpatched WinRAR ACE vulnerability |

---

## 4. Threat Actor/Campaign Attribution

| Attribute | Detail |
|-----------|--------|
| Actor | UAT-6275 (Talos designation) |
| Suspected nexus | Kazakhstan state-sponsored |
| Targeting | CIS government organizations: Kazakhstan, Kyrgyzstan, Tajikistan, Turkmenistan, Uzbekistan, Armenia, Azerbaijan, Russia, Belarus |
| Active period | June 2025 – August 2026 |
| Cluster overlaps | YoroTrooper (assessed as separate Kazakhstan-nexus cluster; shared C2 infrastructure patterns) |
| Motivation | Espionage / intelligence collection against post-Soviet government entities |
| Confidence | Medium — attribution based on infrastructure, targeting profile, and tooling style; no direct government link confirmed publicly |

---

## 5. Splunk Detection Searches

### PS2EXE Compiled Dropper Execution

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process IN ("*ps2exe*", "*PS2EXE*")
    OR (Processes.parent_process_name="powershell.exe" AND Processes.process_name="*.exe" AND Processes.process="*-NonInteractive*")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| where risk_score >= 50
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### GitHub Raw URL Payload Download via PowerShell

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name IN ("powershell.exe", "pwsh.exe")
    AND (Processes.process="*raw.githubusercontent.com*" OR Processes.process="*raw.github.com*")
    AND Processes.process IN ("*DownloadFile*", "*DownloadString*", "*Invoke-WebRequest*", "*iwr*", "*curl*")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=70
| where risk_score >= 50
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

---

## 6. Executive Summary

UAT-6275 is a Kazakhstan-nexus APT cluster tracked by Cisco Talos that conducted a sustained espionage campaign against CIS government organizations from June 2025 through at least August 2026. The group deployed a custom trio of reverse-shell implants — Chvost, Laplas, and PickleShell — through two delivery vectors: macro-laden Word documents and weaponized WinRAR archives exploiting CVE-2025-8088. A distinguishing operational security choice is the use of GitHub as a payload staging platform and the abuse of PS2EXE to compile PowerShell droppers into native executables, bypassing script-block logging and simplifying detection evasion. UAT-6275 shares infrastructure patterns with YoroTrooper, a previously tracked Kazakhstan-nexus cluster, suggesting either cooperation or shared tooling within the Kazakhstan state intelligence apparatus. Nine CIS countries were targeted, indicating a broad mandate to monitor political and diplomatic developments across the former Soviet space. Priority response actions: block execution of PS2EXE tooling, restrict outbound PowerShell connections to raw.githubusercontent.com from managed endpoints, and apply WinRAR patches for CVE-2025-8088.
