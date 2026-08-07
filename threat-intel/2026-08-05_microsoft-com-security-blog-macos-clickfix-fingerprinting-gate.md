---
scraped_at: 2026-08-07T00:00:00Z
source_url: https://www.microsoft.com/en-us/security/blog/2026/08/05/macos-clickfix-campaign-learned-hide/
report_type: threat-intel
severity: high
title: "macOS ClickFix Campaign Adopts Browser-Fingerprinting Gate to Evade Researchers"
---

# Threat Intelligence Report: macOS ClickFix Campaign — Browser-Fingerprinting Gate Delivering AMOS and MacSync (August 2026)

## 1. Indicators of Compromise (IOCs)

### File Hashes
- No file hashes disclosed in the report.

### Domains and URLs

#### ClickFix Lure and Payload Delivery Domains (August 2026)
| Domain | Role |
|--------|------|
| applefilevault[.]com | ClickFix lure / payload delivery |
| apricotfilepoint[.]com | ClickFix lure / payload delivery |
| bananafastfile[.]com | ClickFix lure / payload delivery |
| cloudfilebridge[.]com | ClickFix lure / payload delivery |
| filecedarwallet[.]online | ClickFix lure / payload delivery |
| filecopperbasket[.]sbs | ClickFix lure / payload delivery |
| filecrimsonsignal[.]online | ClickFix lure / payload delivery |
| filemarblegarden[.]sbs | ClickFix lure / payload delivery |
| fileoceanhammer[.]sbs | ClickFix lure / payload delivery |
| filerubyfolder[.]sbs | ClickFix lure / payload delivery |
| filevelvettractor[.]sbs | ClickFix lure / payload delivery |
| lemonfilewave[.]com | ClickFix lure / payload delivery |
| limefilescope[.]com | ClickFix lure / payload delivery |
| mangocloudfile[.]com | ClickFix lure / payload delivery |
| orangesmartfile[.]com | ClickFix lure / payload delivery |
| syncdatavault[.]com | ClickFix lure / payload delivery |
| cloudsendhub[.]com | ClickFix lure / payload delivery |

#### Payload Staging URL Pattern
- `/curl/<id>` — endpoint pattern on delivery domains used for curl-based payload staging (e.g., `https://applefilevault[.]com/curl/abc123`)

### IP Addresses
- No IP addresses disclosed in the report.

### File Names and Paths
- `~/Library/LaunchAgents/com.apple.<random>.plist` — persistence mechanism for dropped payloads
- AMOS (Atomic macOS Stealer): collects browser credentials, macOS Keychain, crypto wallets, and cloud credentials
- MacSync: second infostealer family delivered via this campaign; syncs stolen data over macOS-native APIs

---

## 2. TTPs (MITRE ATT&CK Mapping)

### Resource Development
- **T1583.001 — Acquire Infrastructure: Domains**
  - Operators register short-lived domains with fruit/food-themed naming convention (`apple*`, `banana*`, `lemon*`, `lime*`, `mango*`, `orange*`, etc.) to cycle delivery infrastructure quickly.

### Initial Access
- **T1189 — Drive-by Compromise**
  - Users are directed to ClickFix lure pages via malvertising or redirectors. The lure presents a fake browser verification or CAPTCHA, instructing users to open Terminal and paste a command.

- **T1598 — Phishing for Information** (precursor reconnaissance)
  - Fake CAPTCHA lure harvests browser environment signals (WebGL GPU fingerprint, navigator attributes, platform, screen dimensions, timezone, font enumeration) before serving the ClickFix payload.

### Execution
- **T1204.001 — User Execution: Malicious Link**
  - User manually opens Terminal and pastes a `curl` command pointing to the `/curl/<id>` staging endpoint.

- **T1140 — Deobfuscate/Decode Files or Information**
  - Payload is delivered as a base64-encoded or obfuscated shell script that decodes and executes AMOS or MacSync in memory.

### Defense Evasion
- **T1480.001 — Execution Guardrails: Environmental Keying**
  - **NEW EVASION TECHNIQUE**: Server-side browser-fingerprinting gate inspects JavaScript environment signals before serving the ClickFix lure:
    - WebGL renderer/vendor string (GPU fingerprint) — detects sandbox VMs via GPU vendor strings (e.g., `Mesa`, `llvmpipe`, `SwiftShader`, `VirtualBox`)
    - `navigator.webdriver` — detects Selenium/Playwright automation
    - `toString()` counter checks — detects instrumented environments that intercept native method calls
    - `Array.prototype.includes` tampering checks — detects runtime hooking by security analysis tools
    - Platform, screen dimensions, timezone, and installed font enumeration
  - Gate serves a benign decoy page or HTTP 404 to automated scanners, sandboxes, and research crawlers. Only real macOS browsers on physical hardware with expected GPU values receive the ClickFix payload.

### Credential Access
- **T1056.004 — Input Capture: Credential API Hooking** (AMOS)
  - AMOS hooks macOS Keychain APIs to extract stored credentials without triggering standard Keychain prompts.

- **T1555 — Credentials from Password Stores**
  - Both AMOS and MacSync target browser credential stores (Chrome, Safari, Firefox), macOS Keychain, and crypto wallet files.

### Collection
- **T1005 — Data from Local System**
  - AMOS collects browser credentials, cryptocurrency wallet seed phrases, notes app data, SSH keys, and cloud provider credentials.
  - MacSync synchronizes collected data using macOS-native APIs to attacker-controlled endpoints.

### Exfiltration
- **T1041 — Exfiltration Over C2 Channel**
  - Stolen data exfiltrated to attacker infrastructure via HTTPS.

---

## 3. Malware & Tools

### Malware Families

**AMOS (Atomic macOS Stealer)**
- macOS infostealer targeting browser credentials, Keychain, crypto wallets, and cloud credentials.
- Hooks macOS Keychain APIs for silent credential extraction.
- Active since at least 2023; this campaign represents continued active distribution in 2026.
- Sold as MaaS (Malware-as-a-Service) on Telegram.

**MacSync**
- Second infostealer family delivered by the same ClickFix infrastructure.
- Uses macOS-native APIs for data synchronization/exfiltration.
- Less well-documented than AMOS; appears to be a distinct family co-distributed in this campaign.

### Delivery Infrastructure Pattern
- Domains follow a consistent fruit/food + "file"/"cloud"/"vault"/"sync" naming convention.
- Short TLD rotation: `.com`, `.online`, `.sbs`.
- Payload served only from `/curl/<id>` endpoints after passing the browser-fingerprinting gate.

---

## 4. Threat Actor / Campaign Attribution

### Threat Actor
- **Unknown macOS ClickFix operators (August 2026)**
  - Multiple clusters likely involved; ClickFix lure technique and AMOS are distributed via MaaS model.
  - Sophistication level elevated: adoption of browser-fingerprinting gate to evade sandbox analysis and threat intelligence crawlers represents a meaningful evasion improvement over prior ClickFix campaigns.

### Campaign Evolution
- **July 2026**: Basic ClickFix lure with paid malvertising via `grabora[.]org`, Cloudflare Pages lure domains, bash payloads from short-lived hosting domains (documented in Unit 42 timely threat intel, July 8 2026).
- **August 2026**: Same core technique (fake CAPTCHA → Terminal paste → curl payload) now gated behind a server-side fingerprinting check inspecting WebGL GPU, navigator properties, anti-analysis instrumentation signals, and font/screen dimensions.

### Motivations
- Financial: credential theft for cryptocurrency and banking account takeover; AMOS actively monetized via Telegram MaaS marketplace.

### Targeted Geographies and Sectors
- macOS users globally; no sector-specific targeting observed.
- Crypto holders and individuals with cloud provider credentials are high-value targets.

---

## 5. Splunk Detection Searches

### 5.1 DNS Lookup for Known ClickFix Fingerprinting-Gate Delivery Domains (August 2026)

```spl
| comment "IOC-based: August 2026 macOS ClickFix fingerprinting-gate campaign domains (Microsoft Security Blog 2026-08-05)"
index=* sourcetype IN ("stream:dns","syslog","crowdstrike","cisco:ise:syslog")
    query IN (
        "applefilevault.com",
        "apricotfilepoint.com",
        "bananafastfile.com",
        "cloudfilebridge.com",
        "filecedarwallet.online",
        "filecopperbasket.sbs",
        "filecrimsonsignal.online",
        "filemarblegarden.sbs",
        "fileoceanhammer.sbs",
        "filerubyfolder.sbs",
        "filevelvettractor.sbs",
        "lemonfilewave.com",
        "limefilescope.com",
        "mangocloudfile.com",
        "orangesmartfile.com",
        "syncdatavault.com",
        "cloudsendhub.com")
| eval risk_score=90
| stats count min(_time) as firstTime max(_time) as lastTime
    values(query) as dns_queries by src sourcetype risk_score
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src sourcetype dns_queries risk_score
```

### 5.2 curl Invocation Targeting ClickFix /curl/ Staging Endpoint Pattern

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name="curl"
    AND Processes.process IN ("*/curl/*")
    AND Processes.parent_process_name IN (
        "Terminal","bash","zsh","sh",
        "Safari","Google Chrome","Firefox","Chromium","Brave Browser","Arc")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process,"(?i)/curl/[a-z0-9]{4,}") AND parent_process_name IN ("Safari","Google Chrome","Firefox","Chromium","Brave Browser","Arc"), 90,
    match(process,"(?i)/curl/[a-z0-9]{4,}") AND parent_process_name IN ("bash","zsh","sh","Terminal"), 80,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### 5.3 Browser Spawning curl or Shell (Broad ClickFix Execution — Both July and August 2026 Campaigns)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN (
        "Safari","Google Chrome","Firefox","Chromium","Brave Browser","Arc","Opera","Microsoft Edge")
    AND Processes.process_name IN ("curl","bash","zsh","sh","osascript","python3","python","perl","ruby")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name="osascript", 85,
    process_name="curl" AND match(process,"(?i)/curl/"), 90,
    process_name="curl" AND match(process,"(?i)(\.online|\.sbs|\.top|\.xyz|\.win|\.pro|pages\.dev)"), 85,
    process_name IN ("bash","zsh","sh"), 75,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### 5.4 Web Proxy Request to /curl/ Staging Endpoint

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.uri_path="/curl/*"
    AND Web.http_method="GET"
  by Web.src Web.dest Web.uri_path Web.user_agent Web.http_method Web.url
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(uri_path,"^/curl/[a-z0-9]{4,}$"), 85,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime src dest uri_path user_agent http_method risk_score
```

---

## 6. Executive Summary

An active macOS ClickFix campaign disclosed by Microsoft on August 5, 2026 has meaningfully evolved from prior iterations by adopting a server-side browser-fingerprinting gate to evade sandbox analysis and threat intelligence crawlers. The gate uses JavaScript signals — WebGL GPU renderer strings, `navigator.webdriver`, `toString()` intercept counters, and `Array.prototype.includes` tampering detection — to distinguish real macOS users on physical hardware from automated scanners. Researchers and sandboxes receive a benign decoy page; only users passing the fingerprint check receive the ClickFix lure instructing them to open Terminal and paste a curl command.

The payload staging endpoint follows a consistent `/curl/<id>` URL pattern across 17 newly identified delivery domains registered with a fruit/food-theme naming convention (`.com`, `.online`, `.sbs`). Successful execution installs AMOS (Atomic macOS Stealer) or MacSync, both targeting browser credentials, macOS Keychain entries, cryptocurrency wallets, SSH keys, and cloud provider credentials.

Organizations should block the 17 listed domains at DNS and web proxy layers, alert on macOS browsers spawning curl processes with `/curl/`-path arguments, and correlate curl execution with LaunchAgent plist creation for high-confidence detection of the installation phase.

---

**Related Reports:**
- Previous ClickFix campaign (July 2026): [Unit 42 Timely Threat Intel — macOS ClickFix campaign (July 8, 2026)](https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2026-07-08-macOS-ClickFix-campaign.txt)
