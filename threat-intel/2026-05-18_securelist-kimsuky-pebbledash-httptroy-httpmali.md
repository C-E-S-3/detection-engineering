---
scraped_at: 2026-05-18T00:00:00Z
source_url: https://securelist.com/kimsuky-appleseed-pebbledash-campaigns/119785/
report_type: threat-intel
severity: high
title: "Kimsuky (Velvet Chollima) — New PebbleDash-Based Tools: httpMalice, HttpTroy, MemLoad, and HelloDoor Targeting South Korean Defense and Government"
---

# Kimsuky New PebbleDash Tools: httpMalice, HttpTroy, MemLoad, HelloDoor

## 1. IOCs

### File Hashes — JSE Droppers (MD5)

| Hash | Type | Context |
|------|------|---------|
| `995a0a49ae4b244928b3f67e2bfd7a6e` | MD5 | JSE Dropper variant — Kimsuky PebbleDash cluster delivery |
| `52f1ff082e981cbdfd1f045c6021c63f` | MD5 | JSE Dropper variant |
| `9fe43e08c8f446554340f972dac8a68c` | MD5 | JSE Dropper variant |
| `8e15c4d4f71bdd9dbc48cd2cabc87806` | MD5 | JSE Dropper variant |

### File Hashes — PebbleDash Cluster Malware (SHA-256)

| Hash | Malware | Description |
|------|---------|-------------|
| `e19ce3bd1cbd980082d3c55a4ac1eb3af4d9e7adf108afb1861372f9c7fe0b76` | SCR Dropper | Fake screen saver / VPN invoice lure dropping MemLoad and HttpTroy |
| `20e0db1d2ad90bc46c7074c2cc116c2c08a8183f3ac6f357e7ebee0c7cc02596` | MemLoad V3 | In-memory loader/injector; evolved from prior versions in March and September 2025 |
| `10c3b3ab2e9cb618fc938028c9295ad5bdb1d836b8f07d65c0d3036dbc18bbb4` | HttpTroy | Backdoor DLL; communicates via HTTP POST to C2; full remote access capability |

### C2 Domains and Infrastructure

| Indicator | Context |
|-----------|---------|
| `load.auraria[.]org` | HttpTroy C2 — HTTP POST–based command channel |
| `opedromos1.r-e[.]kr` | JSE Dropper / httpMalice C2 — free South Korean hosting provider |
| `morames.r-e[.]kr` | JSE Dropper / httpMalice C2 |
| `load.ssangyongcne.o-r[.]kr` | httpMalice C2 — hacked legitimate Korean website |
| `load.yju.o-r[.]kr` | httpMalice C2 — hacked legitimate Korean website |
| `attach.docucloud.o-r[.]kr` | httpMalice C2 — hacked legitimate Korean website |
| `load.supershop.o-r[.]kr` | httpMalice C2 — hacked legitimate Korean website |
| `load.erasecloud.n-e[.]kr` | httpMalice C2 — hacked legitimate Korean website |

**Note:** Kimsuky also uses Dropbox cloud storage as a C2 channel for httpMalice, and abuses Cloudflare Quick Tunnels, VS Code Remote Tunneling, and Ngrok to mask their true C2 infrastructure.

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique | ID | Usage |
|--------|-----------|-----|-------|
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 | Spearphishing emails deliver password-protected RAR archives; lures include VPN invoices and purchase orders containing malicious SCR/PIF/JSE/EXE files |
| Execution | User Execution: Malicious File | T1204.002 | Victim executes malicious SCR or JSE file extracted from archive |
| Execution | Command and Scripting Interpreter | T1059 | JSE (JavaScript Script Engine) droppers executed via WScript; SCR PE droppers run directly |
| Defense Evasion | Process Injection | T1055 | MemLoad injects HttpTroy DLL into host process memory |
| Defense Evasion | Masquerading | T1036 | SCR (screen saver) extension used to disguise PE executables; malware masquerades as VPN client or security software |
| Persistence | Boot or Logon Autostart Execution: Registry Run Keys | T1547.001 | Persistence via registry Run key entries |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HttpTroy uses HTTP POST to `load.auraria[.]org`; httpMalice uses HTTP to compromised Korean websites and Dropbox |
| Command and Control | Application Layer Protocol: File Transfer Protocols | T1071.002 | httpMalice uses Dropbox as cloud-based C2 channel for command delivery and output exfiltration |
| Command and Control | Proxy: External Proxy | T1090.002 | Cloudflare Quick Tunnels, VS Code Remote Tunneling, and Ngrok used to obscure C2 infrastructure |
| Collection | Data from Local System | T1005 | HttpTroy collects keystrokes, screenshots, file listings, and credentials |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | Stolen data exfiltrated via existing HTTP POST C2 channel |

---

## 3. Malware & Tools

| Malware | Type | Description |
|---------|------|-------------|
| **httpMalice** | Backdoor (PebbleDash cluster) | Latest PebbleDash-based backdoor; emerged no later than December 2025; deployed by JSE Dropper; uses Dropbox and compromised Korean websites as C2; receives commands and uploads results through session-based HTTP protocol (mode 2/mode 10 messaging pattern) |
| **HttpTroy** | Backdoor DLL | HTTP POST–based RAT providing full remote control; dropped by MemLoad into process memory; communicates with `load.auraria[.]org`; enables command execution, file operations, and credential theft |
| **MemLoad** | In-memory loader / injector | Go-based stub loading HttpTroy DLL into memory; V3 appeared September 2025; avoids disk writes of the final payload |
| **HelloDoor** | Backdoor | Earlier PebbleDash-based backdoor; shares code ancestry with httpMalice |
| **HappyDoor** | Backdoor (AppleSeed cluster) | Companion to AppleSeed; deployed in government-targeting campaigns |
| **AppleSeed** | Backdoor | Established Kimsuky implant targeting government entities |
| **JSE Dropper** | Dropper | JavaScript Script Engine (`.jse`) files used as first-stage droppers; downloaded from password-protected RAR archives delivered via spearphishing |
| **SCR Dropper** | Dropper | Screen saver PE files masquerading as VPN client installers or invoices; drops MemLoad and HttpTroy |

---

## 4. Threat Actor / Campaign Attribution

| Field | Detail |
|-------|--------|
| Actor | **Kimsuky** (aka Velvet Chollima, APT43, Thallium, Black Banshee) |
| Attribution | North Korea–aligned; historically linked to Reconnaissance General Bureau (RGB) or General Bureau of External Intelligence (GBEI) |
| Targeting | South Korean defense sector (primary); government entities; secondary targets in Brazil and Germany |
| Active Since | At least 2012; PebbleDash cluster active since at least 2020 |
| Techniques | Spearphishing via lures (VPN invoices, purchase orders, government forms); JSE/SCR/PIF droppers; custom RATs; VS Code Tunnel and Cloudflare for C2 evasion |
| MITRE Group | [G0094 — Kimsuky](https://attack.mitre.org/groups/G0094/) |

---

## 5. Splunk Detection Searches

### 5.1 HttpTroy / MemLoad — SCR File Execution from User-Writable Directories

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where (Processes.process_name="*.scr" OR match(Processes.process, "\.scr\"?\s"))
  AND NOT (match(Processes.process_path, "(?i)\\\\system32\\\\") OR
           match(Processes.process_path, "(?i)\\\\syswow64\\\\") OR
           match(Processes.process_path, "(?i)\\\\windows\\\\"))
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(Processes.process_path, "(?i)\\\\(users|temp|appdata|downloads)\\\\"), 85,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### 5.2 JSE Dropper Execution — WScript/CScript Launching JS Engine Files

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name IN ("wscript.exe", "cscript.exe")
  AND (match(Processes.process, "\.jse\"?(\s|$)") OR match(Processes.process, "\.vbe\"?(\s|$)"))
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "(?i)temp|appdata|downloads|desktop"), 90,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### 5.3 HttpTroy C2 Domain — DNS Resolution Lookup

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query IN ("load.auraria.org", "opedromos1.r-e.kr", "morames.r-e.kr",
                    "load.ssangyongcne.o-r.kr", "load.yju.o-r.kr",
                    "attach.docucloud.o-r.kr", "load.supershop.o-r.kr",
                    "load.erasecloud.n-e.kr")
by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src query answer risk_score
```

### 5.4 Suspicious HTTP POST from Non-Browser Process to Low-Reputation Domain

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Web.Web
where Web.http_method="POST"
  AND NOT Web.app IN ("msedge.exe", "chrome.exe", "firefox.exe", "iexplore.exe", "safari.exe")
  AND (match(Web.url, "(?i)auraria\.org") OR
       match(Web.url, "(?i)\.r-e\.kr$") OR match(Web.url, "(?i)\.o-r\.kr$") OR
       match(Web.url, "(?i)\.n-e\.kr$"))
by Web.src Web.dest Web.url Web.http_method Web.app Web.user_agent Web.status
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src dest url http_method app user_agent status risk_score
```

### 5.5 VS Code Remote Tunnel / Cloudflare Tunnel Abuse — Non-IDE Process

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name IN ("code.exe", "code-tunnel.exe", "cloudflared.exe", "ngrok.exe")
  AND NOT Processes.parent_process_name IN ("code.exe", "explorer.exe", "services.exe")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=70
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

---

## 6. Executive Summary

Kaspersky researchers disclosed on May 15, 2026 a detailed analysis of new tooling developed by Kimsuky (Velvet Chollima), a North Korea-linked APT group primarily targeting South Korean defense and government organizations. The report reveals three new PebbleDash-based implants — **httpMalice**, **HttpTroy**, and **MemLoad** — alongside the established HelloDoor backdoor and the AppleSeed cluster.

The campaign uses spearphishing emails with password-protected RAR archives delivering malicious SCR (screen saver) or JSE (JavaScript Script Engine) dropper files disguised as VPN invoices, purchase orders, or security software. The SCR dropper delivers **MemLoad**, a Go-based in-memory loader that injects the **HttpTroy** DLL backdoor directly into process memory. **httpMalice**, the newest addition (emerged December 2025), uses compromised South Korean websites and Dropbox cloud storage for C2 communication, bypassing traditional C2 domain blocklists. Kimsuky actively abuses Cloudflare Quick Tunnels, VS Code Remote Tunneling, and Ngrok to conceal their true infrastructure.

Organizations in the South Korean defense and government sectors, and those with connections to Korean critical infrastructure, should hunt for the disclosed IOCs and investigate any execution of SCR files from user directories or WScript execution of `.jse` files.

---

## References

- [Kaspersky Securelist — Disclosing new PebbleDash-based tools by Kimsuky (2026-05-15)](https://securelist.com/kimsuky-appleseed-pebbledash-campaigns/119785/)
- [Gen Digital — DPRK's Playbook: Kimsuky's HttpTroy and Lazarus's New BLINDINGCAN Variant](https://www.gendigital.com/blog/insights/research/dprk-kimsuky-lazarus-analysis)
- [hunt.io — Inside DPRK Operations: New Lazarus and Kimsuky Infrastructure Uncovered](https://hunt.io/blog/dprk-lazarus-kimsuky-infrastructure-uncovered)
- [MITRE ATT&CK — G0094 Kimsuky](https://attack.mitre.org/groups/G0094/)
- [MITRE ATT&CK — T1566.001 Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- [MITRE ATT&CK — T1071.001 Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
