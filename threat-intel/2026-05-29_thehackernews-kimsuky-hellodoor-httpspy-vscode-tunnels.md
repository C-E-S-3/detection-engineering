---
scraped_at: "2026-05-30T00:00:00Z"
source_url: "https://thehackernews.com/2026/05/kimsuky-deploys-httpspy-expands-arsenal.html"
report_type: threat-intel
severity: high
title: "Kimsuky Deploys HelloDoor and New HTTPSpy Variant via VS Code Tunnels, JSONPing, and TryCloudflare C2"
---

## 1. IOCs

### Domains

| Indicator | Type | Role |
|-----------|------|------|
| `female-disorder-beta-metropolitan.trycloudflare[.]com` | Domain | HelloDoor C2 via TryCloudflare temporary tunnel |
| `pyrotech.co[.]kr` | Domain | httpMalice C2 — compromised South Korean website (May 2026 campaign) |
| `newjo-imd[.]com` | Domain | httpMalice C2 — attacker-registered domain (May 2026 campaign) |
| `yespp.co[.]kr` | Domain | httpMalice C2 — compromised South Korean website (May 2026 campaign) |

### Files

| Indicator | Type | Role |
|-----------|------|------|
| `nos-setup.exe` | Filename | Fake nProtect Online Security installer; malicious first-stage dropper |
| `astx-setup.exe` | Filename | Fake AhnLab Safe Transaction (ASTx) installer; malicious first-stage dropper |
| `mTSTCv8.mdxm` | Filename | Intermediate downloader deployed via PowerShell from JSE dropper |
| `engine.dat` | Filename | Next-stage payload fetched by intermediate downloader |
| `spyInster.dll` | Filename | HelloDoor DLL payload (Rust-based backdoor) |

> **Note:** No cryptographic hashes were explicitly published in the primary source. Consumers should pivot on filenames and C2 domains for hunting until official IOC feeds (AhnLab, Enki) publish hashes.

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1566.001 | Phishing: Spearphishing Attachment | JSE dropper delivered via phishing to South Korean military and corporate targets |
| Execution | T1204.002 | User Execution: Malicious File | Victim executes JSE dropper or fake installer EXE |
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | PowerShell used to deploy `mTSTCv8.mdxm` intermediate downloader from dropper |
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Name or Location | Fake nProtect and ASTx installer names impersonating South Korean security software |
| Defense Evasion | T1027 | Obfuscated Files or Information | JSE dropper is obfuscated; intermediate downloader performs anti-analysis checks before continuing |
| Discovery | T1082 | System Information Discovery | JSONPing: malware queries a locally spawned HTTP server via JSONP callback to verify it is running before displaying fake installation UI |
| Command and Control | T1219 | Remote Access Software | VS Code Remote Tunneling and DWAgent (RMM tool) used for persistent post-exploitation remote access |
| Command and Control | T1102.001 | Web Service: Dead Drop Resolver | TryCloudflare temporary tunnels provide HelloDoor with a transient, attribution-resistant C2 channel |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | HelloDoor communicates via HTTP to `*.trycloudflare.com/index.php`; httpMalice communicates via HTTP to compromised Korean websites |
| Command and Control | T1090.003 | Proxy: Multi-hop Proxy | Cloudflare Quick Tunnels proxy HelloDoor traffic through Cloudflare infrastructure before reaching attacker-controlled backend |
| Persistence | T1543 | Create or Modify System Process | DWAgent installed as a persistent service for long-term remote access |

### JSONPing Technique Detail

In one campaign variant Kimsuky's fake installer (masquerading as nProtect/ASTx) spawns a lightweight local HTTP server and then serves the victim a fake installation webpage that makes a **JSONP (JSON with Padding) callback** to `localhost` to check whether the malware process is running. If the callback confirms execution, the page renders a convincing software installation interface; if not, the dropper relaunches. This technique:
- Provides execution verification without generating external network traffic
- Defeats sandbox analysis if the dropper is not run in user-context
- Makes the fake UI contextually credible to the victim

---

## 3. Malware & Tools

| Name | Type | Key Details |
|------|------|-------------|
| **HelloDoor** | DLL Backdoor (Rust) | PebbleDash variant; first seen August 2025; likely LLM-assisted development; deployed via JSE dropper; C2 via TryCloudflare temporary tunnel; single DLL (`spyInster.dll`) loaded via intermediate downloader |
| **HTTPSpy (new variant)** | Remote Access Trojan | Three-stage execution chain (Installer → Loader → HttpSpy DLL) replacing prior single-binary architecture; full RAT capability: shell commands, file upload/download, process execution, screenshot capture, DLL injection into PID |
| **httpMalice** | Backdoor | Communicates to compromised South Korean `.co.kr` websites and attacker-registered domains as C2; same PebbleDash cluster as HttpTroy |
| **mTSTCv8.mdxm** | Intermediate Downloader | PowerShell-deployed; performs anti-analysis checks; fetches `engine.dat` or `spyInster.dll` from C2 |
| **DWAgent** | Legitimate RMM Tool (abused) | Open-source remote monitoring and management tool installed for persistent post-exploitation access |
| **VS Code Remote Tunneling** | Legitimate Dev Tool (abused) | Microsoft Visual Studio Code tunnel feature combined with GitHub authentication used as covert C2 channel; traffic blends with developer tooling |

---

## 4. Threat Actor / Campaign Attribution

| Field | Value |
|-------|-------|
| **Threat Actor** | Kimsuky (aka Velvet Chollima, APT43, Thallium, Black Banshee) |
| **Attribution Confidence** | High — consistent tooling, targeting, and infrastructure patterns with prior Kimsuky campaigns |
| **State Sponsor** | DPRK (North Korea) — Reconnaissance General Bureau (RGB) |
| **Targets** | South Korean military entities and corporate organizations; March–April 2026 campaign window |
| **Primary Research Source** | Enki White Hat (South Korean security firm): "Kimsuky's Advanced Attack Techniques: JSONPing, Webex Spoofing, and a New HttpSpy Variant" |

**Delivery method variants observed:**
1. Fake nProtect/ASTx installer page served via compromised or attacker-controlled website → victim downloads and runs `nos-setup.exe` / `astx-setup.exe`
2. Fake Cisco Webex meeting page delivering a script that retrieves a ZIP with an encrypted JavaScript file → JSE dropper execution leading to HTTPSpy

**Campaign differentiators from prior Kimsuky activity:**
- HelloDoor represents a new Rust-based implant (LLM-assisted), expanding beyond Go/C++ tools
- TryCloudflare temporary tunnels replace persistent attacker-controlled C2 domains for HelloDoor, complicating infrastructure takedowns
- JSONPing is a novel anti-sandbox execution-verification technique
- DWAgent + VS Code tunneling add a "living-off-trusted-tools" post-exploitation layer

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query IN (
    "female-disorder-beta-metropolitan.trycloudflare.com",
    "pyrotech.co.kr",
    "newjo-imd.com",
    "yespp.co.kr"
    )
by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src query answer risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name IN ("nos-setup.exe","astx-setup.exe","mTSTCv8.mdxm")
   OR (Processes.process_name="powershell.exe" AND Processes.process="*mTSTCv8*")
by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query="*.trycloudflare.com"
by DNS.src DNS.query DNS.answer DNS.process_name
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name IN ("chrome.exe","firefox.exe","msedge.exe","safari","curl","wget"), 20,
    1=1, 70)
| where risk_score >= 50
| table firstTime lastTime src query answer process_name risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="code.exe" OR Processes.process_name="code"
   AND Processes.process IN ("*tunnel*","*--tunnel*","*devtunnel*")
by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    parent_process_name IN ("cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe"), 80,
    1=1, 40)
| where risk_score >= 50
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

---

## 6. Executive Summary

Kimsuky (DPRK/RGB) has expanded its malware toolkit and TTPs in a March–April 2026 campaign targeting South Korean military and corporate entities. The campaign introduces **HelloDoor**, a new Rust-based DLL backdoor likely developed with LLM assistance, as well as a restructured three-stage **HTTPSpy** variant and a novel execution-verification trick dubbed **JSONPing** that queries a local HTTP server via JSONP to confirm malware execution before displaying fake software installation UI.

The most operationally significant development is Kimsuky's adoption of **TryCloudflare temporary tunnels** for HelloDoor C2 and **VS Code Remote Tunneling** with GitHub authentication for post-exploitation persistent access. These legitimate developer services make C2 traffic indistinguishable from developer workflows in environments where VS Code and Cloudflare tools are commonly used, and Cloudflare tunnels rotate URLs on demand, defeating traditional IOC-based domain blocklisting.

Defenders should monitor for:
- DNS resolution of `*.trycloudflare.com` from non-browser processes
- VS Code (`code.exe`) invoked with `--tunnel` flags from script interpreters
- Fake Korean security software installer names (`nos-setup.exe`, `astx-setup.exe`)
- DWAgent installation from unexpected parent processes

---

## References

- [The Hacker News — Kimsuky Deploys HTTPSpy, Expands Arsenal with HelloDoor and VS Code Tunnels (2026-05-29)](https://thehackernews.com/2026/05/kimsuky-deploys-httpspy-expands-arsenal.html)
- [Enki White Hat — Kimsuky's Advanced Attack Techniques: JSONPing, Webex Spoofing, and a New HttpSpy Variant](https://www.enki.co.kr/en/media-center/blog/kimsuky-s-advanced-attack-techniques-jsonping-webex-spoofing-and-a-new-httpspy-variant)
- [Kaspersky Securelist — Disclosing new PebbleDash-based tools by Kimsuky (2026-05-15)](https://securelist.com/kimsuky-appleseed-pebbledash-campaigns/119785/)
- [MITRE ATT&CK — G0094 Kimsuky](https://attack.mitre.org/groups/G0094/)
- [CISA — North Korean Threat Actor Kimsuky Advisory (AA20-301A)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-301a)
