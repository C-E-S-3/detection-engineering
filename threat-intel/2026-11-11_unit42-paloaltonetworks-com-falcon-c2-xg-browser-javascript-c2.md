---
scraped_at: 2026-11-12T00:00:00Z
source_url: https://unit42.paloaltonetworks.com/falcon-c2-browser-compromise/
report_type: threat-intel
severity: high
title: "Falcon C2 (XG / Xiàng Gē): Browser-Based JavaScript C2 Framework Targeting Government Web Applications in Middle East and Southeast Asia"
---

## 1. IOCs

### Domains / Infrastructure
No specific C2 domains confirmed from secondary sources. Full IOC list in Unit 42 primary report appendix.

### Behavioral Indicators
| Pattern | Context |
|---------|---------|
| WebSocket upgrade (101 Switching Protocols) from browser to external host, with heartbeat traffic every ~60 seconds | Falcon C2 implant heartbeat |
| Comet protocol long-poll HTTP requests from browser to external endpoint | Falcon C2 fallback transport |
| JavaScript served by webmail/government portal containing unique per-session obfuscated code payload | Server-side implant generation |
| Malicious Chrome browser extension installation followed by lateral access to government webmail | One confirmed initial access vector |

## 2. TTPs

### MITRE ATT&CK

| Tactic | Technique | ID | Usage |
|--------|-----------|-----|-------|
| Initial Access | Drive-by Compromise | T1189 | Victims visiting compromised government web applications or webmail portals served uniquely obfuscated JavaScript implant |
| Initial Access | Browser Extensions | T1176 | In at least one case, malicious Chrome extension used to establish initial access to target webmail portal |
| Execution | JavaScript | T1059.007 | Per-session obfuscated JavaScript implant executed within victim browser context |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | TLS-encrypted WebSocket channel used as primary C2 transport |
| Command and Control | Encrypted Channel | T1573 | TLS wraps all C2 communications; implant blends into legitimate HTTPS web traffic |
| Command and Control | Web Service: Bidirectional Communication | T1102.002 | Comet long-poll fallback for environments blocking WebSocket upgrades; also delivers Antino backdoor for persistent access |
| Collection | Browser Session Hijacking | T1185 | JavaScript implant harvests browser session tokens, cookies, and credentials from within the browser process |
| Credential Access | Credentials from Web Browsers | T1555.003 | Credential and password data stolen from browser credential stores via in-process JavaScript |
| Defense Evasion | Obfuscated Files or Information | T1027 | Implant is uniquely re-obfuscated per browser session by the NodeJS server, defeating static signature detection |

### Framework Architecture
- **Server:** NodeJS application with two separate listeners (operator interface + implant delivery)
- **Implant generation:** Server generates a unique obfuscation layer per browser session at delivery time
- **Transport:** TLS WebSocket (primary); Comet long-poll HTTP (fallback)
- **Heartbeat:** Every 60 seconds
- **Capability delivery:** Also deploys Antino Rust backdoor for persistent OS-level access
- **Relationship:** Unit 42 assesses Falcon and PeckBirdy as variants of the same core framework

### Targeted Environments
- Webmail portals (government-operated)
- Government web applications
- National justice department affiliated entity (confirmed case, SE Asia)
- Intrusion window observed: March–May 2026

## 3. Malware & Tools

| Name | Type | Notes |
|------|------|-------|
| Falcon (XG / Xiàng Gē) | Browser-based JavaScript C2 framework | NodeJS server; per-session obfuscated JS implant; TLS WebSocket + Comet C2 |
| PeckBirdy | Browser C2 variant | Assessed by Unit 42 as variant of Falcon's core framework |
| Antino | Rust backdoor | Delivered by Falcon post-compromise for persistent OS-level access via Microsoft Graph API dead-drop C2 |

## 4. Threat Actor / Campaign Attribution

| Attribute | Detail |
|-----------|--------|
| Cluster | Unattributed (suspected nation-state) |
| Targeting | Government entities in 1 Middle Eastern country and 4 Southeast Asian countries |
| Campaign window | March – May 2026 (from Unit 42 visibility) |
| Nexus | Suspected state-sponsored; Falcon shares tooling with Antino delivery (UAT-11587 overlap) |
| Access pattern | Compromised webmail portals and government web applications; Chrome extension as one initial access vector |

## 5. Splunk Detection Searches

### WebSocket Upgrade Followed by Unusual Long-Poll HTTP (Browser-Based C2)

```spl
`sysmon` EventCode=3
(dest_port=443 OR dest_port=80)
process_name IN ("chrome.exe","msedge.exe","firefox.exe","iexplore.exe","brave.exe")
| eval conn_key=mvappend(src_ip, dest_ip, process_name)
| stats count min(_time) as firstTime max(_time) as lastTime dc(dest_ip) as unique_dests
  by src_ip process_name process_id
| where count >= 60 AND unique_dests <= 3
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval session_duration_minutes=round((lastTime-firstTime)/60,1)
| where session_duration_minutes >= 5
| eval risk_score=case(session_duration_minutes >= 60, 75, 1=1, 55)
| table firstTime lastTime src_ip process_name process_id unique_dests count session_duration_minutes risk_score
```

> Detects sustained browser connections to a small set of unique external IP addresses suggesting WebSocket/Comet long-poll C2 channels. High false-positive risk; tune to exclude known collaboration and streaming platforms.

### Malicious Chrome Extension Installation (Unexpected Source)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_path="*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Extensions\\*\\manifest.json"
  AND Filesystem.action="created"
by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=50
| where risk_score >= 50
| table firstTime lastTime dest user file_path risk_score
```

> Detects new Chrome extension installations by monitoring manifest.json file creation in extension directories. Useful for identifying unauthorized extension installs used as Falcon C2 initial access vectors. Correlate with extension source and permission scope.

## 6. Executive Summary

Unit 42 published (November 11, 2026) a detailed analysis of **Falcon C2**, also known as XG or Xiàng Gē, a browser-based command-and-control framework that compromises government web applications by injecting malicious JavaScript into webmail portals and government websites. When victims visit these compromised pages, their browsers receive a uniquely obfuscated JavaScript implant that establishes a TLS-encrypted WebSocket channel (with Comet long-poll fallback) back to attacker infrastructure — blending entirely into normal HTTPS browsing traffic.

The framework is built on NodeJS and generates a fresh, uniquely obfuscated version of the implant for each browser session, defeating static signatures. Collected credentials and session cookies are exfiltrated via the same channel. Post-compromise, Falcon deploys the **Antino** Rust backdoor (see companion report) for persistent OS-level access via Microsoft Graph API email dead-drop C2.

Intrusions were observed between March and May 2026, compromising government entities in one Middle Eastern and four Southeast Asian countries. Unit 42 assesses Falcon and PeckBirdy as variants of the same underlying framework. At least one intrusion began via a malicious Chrome browser extension.

**Recommended actions:** Audit webmail portal code for injected JavaScript; enforce browser extension whitelisting via enterprise policy; monitor WebSocket upgrades from browser processes to unexpected external hosts; review Content-Security-Policy (CSP) headers for government web applications.
