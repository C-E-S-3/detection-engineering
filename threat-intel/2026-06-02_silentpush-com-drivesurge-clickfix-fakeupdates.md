---
scraped_at: 2026-06-03T00:00:00Z
source_url: https://www.silentpush.com/blog/drivesurge/
report_type: threat-intel
severity: high
title: "DriveSurge: New Initial Access Broker Hijacks Thousands of Websites for Large-Scale ClickFix and FakeUpdates Drive-By Campaigns"
---

## 1. IOCs

### IP Addresses

| Indicator | Context |
|-----------|---------|
| 91.92.240[.]127 | DriveSurge — ClickFix payload delivery server; bulletproof hosting; observed serving malicious clipboard-injection PowerShell in confirmed ClickFix lure instances |

### Domains

| Indicator | Context |
|-----------|---------|
| ycyfugihih[.]cfd | DriveSurge registrant infrastructure email domain — `thiagorivera197151[@]ycyfugihih[.]cfd` used to register 82+ DriveSurge injection domains; domain itself registered via bulletproof registrar |

### Behavioral IOCs

- JavaScript injection following the pattern `t.js?site=<id>` loaded from DriveSurge-controlled domain into compromised websites; `<id>` is a unique per-site campaign identifier
- Outbound HTTPS requests from website visitors routed through **zTDS** (an open-source Traffic Distribution System in use by DriveSurge since at least September 2025)
- FakeUpdates lure: DOM overlay injected into compromised websites mimicking a browser update dialog for Chrome, Firefox, Edge, Safari, Opera, Brave, Vivaldi, Samsung Internet, UC Browser, or Yandex Browser
- ClickFix lure: clipboard injection payload instructing users to paste a command into Windows Run (Win+R) or Terminal; observed pulling malicious code from 91.92.240[.]127
- Pre-weaponized infrastructure: 7 of 39 unique injection domains were registered but not yet serving payloads as of early June 2026 — future activation expected

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1189 | Drive-by Compromise | DriveSurge injects malicious JavaScript into thousands of compromised websites; visitors are silently profiled by zTDS and served either a ClickFix or FakeUpdates lure based on their browser, OS, and geolocation |
| Initial Access | T1659 | Content Injection | `t.js?site=<id>` script injected into compromised sites; renders fake browser update overlays or ClickFix CAPTCHA prompts on top of legitimate page content |
| Execution | T1204.002 | User Execution: Malicious File | FakeUpdates variant: victim clicks "Download Update" → downloads and executes a `.js` or `.exe` fake browser update installer; executed via Windows Script Host or directly from Explorer |
| Execution | T1204 | User Execution | ClickFix variant: victim pastes attacker-supplied command into Windows Run (Win+R) or Terminal, executing a PowerShell one-liner |
| Defense Evasion | T1027 | Obfuscated Files or Information | zTDS fingerprints visitors (browser, OS, IP, screen resolution) to avoid serving payloads to security scanners and sandboxes; only qualifying targets receive malicious content |
| Resource Development | T1583.001 | Acquire Infrastructure: Domains | 82+ injection domains registered via bulletproof registrars, many using the `thiagorivera197151[@]ycyfugihih[.]cfd` email address; 7 domains pre-weaponized but inactive |
| Resource Development | T1584.004 | Compromise Infrastructure: Server | Thousands of legitimate websites compromised with persistent JavaScript injection; DriveSurge operates as a Pay-Per-Install (PPI) service — compromised site infrastructure is leased to downstream malware operators |
| Command and Control | T1090 | Proxy | zTDS acts as an intermediary Traffic Distribution System, routing qualifying victims through multiple hops before delivering the final payload or ClickFix lure |

**Attack Flow (FakeUpdates path):**
1. Victim visits a legitimate website compromised by DriveSurge.
2. Hidden JavaScript (`t.js?site=<id>`) loads from a DriveSurge injection domain.
3. zTDS profiles the visitor (OS, browser, IP, referrer).
4. Qualifying visitors see a convincing browser update overlay ("Your Chrome is out of date — Download Update").
5. Victim clicks "Download Update" → receives a `.js` or `.exe` fake installer.
6. Installer executes via Windows Script Host (`.js`) or Explorer (`.exe`), dropping the downstream malware payload (SocGholish/DRIDEX/DOPPELPAYMER/etc.).

**Attack Flow (ClickFix path):**
1. Steps 1–3 same as above.
2. Qualifying visitors see a fake CAPTCHA or document-preview page instructing them to copy/paste a command.
3. Command is auto-copied to clipboard; victim pastes into Windows Run dialog.
4. PowerShell one-liner contacts 91.92.240[.]127 or other delivery server and executes stage-2 payload.

## 3. Malware & Tools

| Malware/Tool | Description |
|-------------|-------------|
| FakeUpdates (SocGholish) | Drive-by initial access malware delivered as a fake browser update `.js` file; serves as initial access for downstream loaders and ransomware |
| DRIDEX | Banking trojan / loader historically delivered via FakeUpdates/SocGholish (linked to Evil Corp) |
| DOPPELPAYMER | Ransomware (Evil Corp-linked) historically distributed via FakeUpdates/SocGholish/DRIDEX chain |
| CHTHONIC | Banking trojan sometimes distributed in FakeUpdates chains |
| zTDS | Open-source Traffic Distribution System (TDS) used since at least 2015; DriveSurge has operated it since at least September 2025 for victim fingerprinting and payload routing |

## 4. Threat Actor / Campaign Attribution

| Attribute | Detail |
|-----------|--------|
| Threat Actor | DriveSurge (newly named by Silent Push, June 2026) |
| Type | Initial Access Broker (IAB) operating a Pay-Per-Install (PPI) model |
| Operating model | Specializes in large-scale web-based drive-by compromise; sells qualified victim sessions and installs to downstream threat actors (ransomware operators, credential thieves, etc.) |
| Infrastructure scale | Thousands of compromised websites used as delivery nodes; 82+ attacker-controlled injection domains identified; 90 total hostnames (39 unique after subdomain deduplication) |
| Fingerprints | 8 technical fingerprints documented by Silent Push; primary signature: `t.js?site=<id>` injection pattern with per-site unique identifier |
| Active since | At least September 2025 (earliest observed zTDS use attributed to DriveSurge) |
| Related actors | Downstream customers likely include Evil Corp affiliates (DRIDEX/DOPPELPAYMER nexus) and ransomware-as-a-service operators; DriveSurge itself does not appear to operate the downstream malware |

## 5. Splunk Detection Searches

```spl
| comment "Search 1: DriveSurge FakeUpdates — wscript.exe or cscript.exe executing .js files from user Downloads or Temp directories (fake browser update installer)"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("wscript.exe","cscript.exe")
    AND (Processes.process="*\\Downloads\\*.js*"
         OR Processes.process="*\\AppData\\Local\\Temp\\*.js*"
         OR Processes.process="*\\Users\\Public\\*.js*"
         OR Processes.process="*Update*.js*"
         OR Processes.process="*Browser*.js*"
         OR Processes.process="*Chrome*.js*"
         OR Processes.process="*Firefox*.js*"
         OR Processes.process="*Edge*.js*")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "(?i)update.*\.js|browser.*\.js|chrome.*\.js|firefox.*\.js|edge.*\.js"), 90,
    match(process, "(?i)\\\\Downloads\\\\.*\.js"), 85,
    match(process, "(?i)\\\\Temp\\\\.*\.js"), 80,
    1=1, 70)
| where risk_score >= 80
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| comment "Search 2: DriveSurge ClickFix delivery — PowerShell pulling content from bulletproof hosting IP 91.92.240.127"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest="91.92.240.127"
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src dest dest_port app risk_score
```

```spl
| comment "Search 3: DriveSurge FakeUpdates — browser spawning wscript, cscript, or direct .js execution (drive-by to user execution chain)"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("chrome.exe","msedge.exe","firefox.exe","iexplore.exe",
      "opera.exe","brave.exe","vivaldi.exe","safari.exe")
    AND Processes.process_name IN ("wscript.exe","cscript.exe","msiexec.exe","rundll32.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name, "(?i)wscript|cscript") AND match(parent_process_name, "(?i)chrome|edge|firefox|opera|brave"), 92,
    match(process_name, "(?i)msiexec") AND match(parent_process_name, "(?i)chrome|edge|firefox"), 85,
    1=1, 75)
| where risk_score >= 85
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| comment "Search 4: DriveSurge zTDS fingerprinting beacon — HTTP requests to injection domains matching t.js?site= pattern (via proxy/web logs)"
`fortigate` OR `proxy`
| where (uri LIKE "%t.js%site=%" OR url LIKE "%t.js%site=%")
| eval risk_score=80
| stats count min(_time) as firstTime max(_time) as lastTime by src_ip, dest_host, uri, user_agent
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src_ip dest_host uri user_agent risk_score
```

**Tuning notes:**
- Search 1: FakeUpdates `.js` execution from Downloads/Temp is high-fidelity; tune by excluding known legitimate MSI/NSIS installers that use wscript in temp paths.
- Search 2: Traffic to 91.92.240.127 from any endpoint should be treated as high-confidence DriveSurge ClickFix infection.
- Search 3: Browser → wscript/cscript chain has near-zero false positives in most enterprise environments. Tune out known software deployment tools.
- Search 4: Requires proxy/web gateway log sources indexed in Splunk. Match is based on URI pattern, not specific domain, making it resilient to domain rotation.

## 6. Executive Summary

Silent Push published research on June 2, 2026 naming **DriveSurge** as the threat actor behind a large-scale surge in **ClickFix** and **FakeUpdates** drive-by compromise campaigns. DriveSurge is a newly identified **Initial Access Broker (IAB)** operating a **Pay-Per-Install (PPI)** model: it maintains a network of thousands of compromised legitimate websites injected with malicious JavaScript that routes visitors through a Traffic Distribution System (zTDS), fingerprints them, and delivers either a ClickFix lure (paste-to-run clipboard injection) or a FakeUpdates lure (fake browser update installer download).

**Scale and infrastructure:** Silent Push identified 8 technical fingerprints linking DriveSurge infrastructure, discovering 90 hostnames (39 unique after subdomain deduplication) and 82 unique injection domains — 7 of which were registered but not yet serving payloads, indicating pre-staged expansion infrastructure. The primary infrastructure fingerprint is the `t.js?site=<id>` JavaScript injection pattern loaded from DriveSurge-controlled domains.

**Payloads:** Confirmed downstream payloads include **FakeUpdates/SocGholish** (the initial `.js` installer), which historically leads to DRIDEX banking trojan, DOPPELPAYMER ransomware, CHTHONIC, KOADIC, and other malware families operated by DriveSurge's downstream criminal customers. This threat actor essentially industrializes the initial access step and sells qualified access to other criminal operators.

**Detection priority:** The FakeUpdates vector (wscript.exe executing `.js` files from user download directories, or browser processes spawning wscript) is highly detectable at the endpoint and rarely produces false positives in enterprise environments. Defenders should prioritize Searches 1 and 3 as low-noise, high-fidelity rules.

## References

- [Silent Push — Meet DriveSurge: A New Threat Actor Using ClickFix and Fake Update Drive-By Attacks in Thousands of Compromised Sites (2026-06-02)](https://www.silentpush.com/blog/drivesurge/)
- [BleepingComputer — Hackers hijack thousands of sites for ClickFix and FakeUpdate attacks](https://www.bleepingcomputer.com/news/security/hackers-hijack-thousands-of-sites-for-clickfix-and-fakeupdate-attacks/)
- [Dark Reading — DriveSurge Hijacks Thousands of Sites for ClickFix, FakeUpdate Attacks](https://www.darkreading.com/cyberattacks-data-breaches/drivesurge-hijacks-thousands-sites-clickfix-fakeupdate-attacks)
- [TechRadar — Thousands of compromised websites abused by DriveSurge](https://www.techradar.com/pro/security/thousands-of-compromised-websites-abused-by-drivesurge-in-active-clickfix-and-fakeupdates-campaigns)
- [MITRE ATT&CK — T1189 Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)
- [MITRE ATT&CK — T1659 Content Injection](https://attack.mitre.org/techniques/T1659/)
- [MITRE ATT&CK — T1204.002 User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [Malpedia — FakeUpdates / SocGholish](https://malpedia.caad.fkie.fraunhofer.de/details/js.fakeupdates)
