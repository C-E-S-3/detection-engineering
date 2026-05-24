---
scraped_at: 2026-05-24T00:00:00Z
source_url: https://www.pwc.com/gx/en/issues/cybersecurity/cyber-threat-intelligence/red-lamassu-open-season.html
report_type: threat-intel
severity: high
title: "Red Lamassu (Calypso APT) Targets Telecom with Showboat Linux Backdoor and JFMBackdoor Windows Implant"
---

# Red Lamassu (Calypso APT) Targets Telecom with Showboat Linux Backdoor and JFMBackdoor Windows Implant

PwC Threat Intelligence and Lumen Black Lotus Labs published coordinated research on May 21, 2026 exposing a China-based APT actor tracked as **Red Lamassu** (also known as **Calypso APT**) deploying two previously undocumented malware families — **Showboat** (Linux) and **JFMBackdoor** (Windows) — against telecommunications providers in Afghanistan, Azerbaijan, Kazakhstan, and India, as well as broader Asia-Pacific and Middle East targets. The campaign has been active since at least mid-2022, with C2 infrastructure correlated to IP addresses geolocated to Chengdu, Sichuan Province, China.

---

## 1. IOCs

### Domains

| Indicator | Description |
|-----------|-------------|
| `namefuture[.]site` | JFMBackdoor Windows implant C2 domain |
| `newsprojects[.]online` | Showboat/kworker Linux implant C2 domain; CloudFlare certificate observed on associated IPs |

### IP Addresses

| Indicator | Description |
|-----------|-------------|
| `23.27.201.160` | Open directory hosting Showboat kworker samples and JFMBackdoor; active July–October 2025 |
| `166.88.11[.]196` | C2 server serving CloudFlare certificate associated with newsprojects[.]online |
| `139.180.223[.]193` | C2 server serving CloudFlare certificate associated with newsprojects[.]online |

### X.509 Certificate Fingerprints

| Indicator | Description |
|-----------|-------------|
| `27df475626aafce2ea1548a9f35efb9ad951298c8b11a6adb3ccdfcd5170c677` | Self-signed cert using "My Organization" metadata; observed on Red Lamassu C2 infrastructure |
| `2229e7f3cabbce4d67cd79c89fd5a100b20e8a99f4a2bf9aac77a978f49eb520` | Self-signed cert fingerprint observed across multiple Red Lamassu C2 IPs |

### File Artifacts

| Indicator | Description |
|-----------|-------------|
| `C:\Users\public\jfm` | Hardcoded file path within JFMBackdoor; basis for malware name |
| `kworker` | Showboat Linux implant masquerades as Linux kernel worker thread process name |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Defense Evasion | TA0005 | T1574.002 | DLL Side-Loading — JFMBackdoor delivered by hijacking a legitimate application's DLL search path |
| Defense Evasion | TA0005 | T1036.005 | Masquerading: Match Legitimate Name or Location — Showboat disguises itself as `kworker`, a standard Linux kernel worker thread |
| Command and Control | TA0011 | T1090.001 | Proxy: Internal Proxy — Showboat functions as a SOCKS5 proxy, tunneling traffic from victim networks through compromised systems |
| Command and Control | TA0011 | T1071.001 | Application Layer Protocol: Web Protocols — JFMBackdoor and Showboat communicate with C2 over HTTP/HTTPS |
| Collection | TA0009 | T1113 | Screen Capture — JFMBackdoor includes screenshot capture functionality |
| Collection | TA0009 | T1083 | File and Directory Discovery — Showboat supports directory traversal and file listing |
| Lateral Movement | TA0008 | T1021.001 | Remote Services: SSH — Showboat file transfer capability used for lateral movement support |
| Execution | TA0002 | T1059.004 | Command and Scripting Interpreter: Unix Shell — Showboat spawns remote Unix shell on compromised Linux systems |
| Execution | TA0002 | T1059.003 | Command and Scripting Interpreter: Windows Command Shell — JFMBackdoor provides interactive Windows shell |
| Defense Evasion | TA0005 | T1070.004 | Indicator Removal: File Deletion — JFMBackdoor supports self-removal to limit forensic evidence |
| Persistence | TA0003 | T1543.003 | Create or Modify System Process: Windows Service — JFMBackdoor likely installed as a service to survive reboots |

---

## 3. Malware & Tools

### Showboat (Linux)
- **Type:** Modular post-exploitation framework / SOCKS5 backdoor
- **Platform:** Linux ELF binary
- **Capabilities:** Remote shell, file upload/download, SOCKS5 proxy forwarding
- **Evasion:** Named `kworker` to blend with kernel worker threads; designed for long-term persistent access

### JFMBackdoor (Windows)
- **Type:** Fully-featured Windows backdoor
- **Delivery:** DLL side-loading via legitimate host application
- **Capabilities:** Remote shell, file system operations, network proxying, screenshot capture, self-removal
- **C2:** Communicates with `namefuture[.]site`
- **Artifact:** Hardcoded path `C:\Users\public\jfm`

---

## 4. Threat Actor / Campaign Attribution

| Attribute | Detail |
|-----------|--------|
| Actor | Red Lamassu (also tracked as Calypso, Calypso APT) |
| Origin Assessment | China-nexus; infrastructure geolocated to Chengdu, Sichuan Province |
| Targets | Telecommunications providers, internet service providers (ISPs) |
| Target Geographies | Afghanistan, Azerbaijan, Kazakhstan, India; broader Asia-Pacific and Middle East |
| Campaign Duration | Active since at least mid-2022 |
| Victims Confirmed | Afghanistan-based ISP; unknown entity in Azerbaijan |
| Intelligence Goal | Long-term persistent access for intelligence collection against telecom infrastructure |

Red Lamassu / Calypso APT was previously associated with attacks against government entities in Central Asia. The telecom sector targeting aligns with known Chinese intelligence collection priorities in the region, particularly around Afghanistan post-2021.

---

## 5. Splunk Detection Searches

### Search 1 — Network connections to Red Lamassu C2 domains and IPs
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where (All_Traffic.dest_ip IN ("23.27.201.160","166.88.11.196","139.180.223.193")
    OR All_Traffic.dest_domain IN ("namefuture.site","newsprojects.online"))
by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.dest_domain All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src_ip dest_ip dest_port dest_domain app risk_score
```

### Search 2 — DNS resolution of Red Lamassu C2 domains
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query IN ("namefuture.site","newsprojects.online","*.namefuture.site","*.newsprojects.online")
by DNS.src DNS.query DNS.answer DNS.record_type
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src query answer record_type risk_score
```

### Search 3 — JFMBackdoor DLL side-loading indicator (C:\Users\public\jfm artifact)
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_path="C:\\Users\\public\\jfm*"
    OR Filesystem.file_path="*\\jfm\\*"
by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.action
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| where risk_score >= 95
| table firstTime lastTime dest user file_name file_path action risk_score
```

### Search 4 — Linux process masquerading as kworker from non-kernel path
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="kworker"
  AND NOT (Processes.process_path IN ("/usr/lib/systemd/*","/kthread*","[kworker*"))
by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| where risk_score >= 85
| table firstTime lastTime dest user process_name process_path process risk_score
```

---

## 6. Executive Summary

PwC Threat Intelligence and Lumen Black Lotus Labs jointly disclosed a multi-year China-nexus espionage campaign by **Red Lamassu** (Calypso APT) targeting telecommunications providers in Central Asia and the Middle East. The actor deploys two custom malware families: **Showboat**, a modular Linux ELF backdoor masquerading as a kernel worker thread with SOCKS5 proxy capability for deep network tunneling, and **JFMBackdoor**, a fully-featured Windows implant delivered via DLL side-loading that provides persistent interactive access, screenshot capture, and self-removal. C2 infrastructure includes the domains `namefuture[.]site` and `newsprojects[.]online`, backed by IPs in the `23.27.201.0/24` and `166.88.11.0/24` ranges. Defenders should hunt for `kworker` processes outside standard kernel paths, SOCKS5 proxy traffic from unexpected hosts, DLL side-loading indicators, and network connections to the listed IOCs.

---

## References

- [PwC TI — Open Directory, Open Season: Inside Red Lamassu's JFMBackdoor](https://www.pwc.com/gx/en/issues/cybersecurity/cyber-threat-intelligence/red-lamassu-open-season.html)
- [Lumen Black Lotus Labs — Introducing Showboat](https://www.lumen.com/blog/en-us/introducing-showboat-a-new-malware-family-taunts-defenses-and-targets-international-telecom-firms)
- [PwC GitHub IOC Repository](https://github.com/PwCUK-CTO/TI-blog-2026-Red-Lamassu-JFMBackdoor)
- [MITRE ATT&CK — Calypso Group](https://attack.mitre.org/groups/)
- [The Hacker News — Showboat Linux Malware Hits Middle East Telecom](https://thehackernews.com/2026/05/showboat-linux-malware-hits-middle-east.html)
