---
scraped_at: "2026-08-26T08:00:00Z"
source_url: "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/osx_nova.txt"
report_type: threat-intel
severity: high
title: "LumaNotch macOS Infostealer Campaign — Fake 'Dynamic Island' App Delivers Miolab/PamStealer (Aug 2026)"
---

# LumaNotch macOS Infostealer Campaign — Fake "Dynamic Island" App Delivers Miolab/PamStealer

**Source:** Maltrail `osx_nova.txt` trail (stamparm/maltrail); commits 2026-08-24 through 2026-08-26  
**Attribution reference:** [@L0Psec on X (Twitter)](https://x.com/L0Psec/status/2079591997610791192)  
**Severity:** High  
**Malware family:** Miolab Stealer / PamStealer / CrashStealer (macOS infostealer; same codebase, multiple branding waves)

---

## 1. IOCs

### Domains

| Indicator | Context |
|-----------|---------|
| `lumanotch[.]cc` | Primary lure and delivery domain — "LumaNotch – Dynamic Island for macOS" fake app; registered August 2026 |
| `lumanotch[.]pro` | Secondary lure/delivery domain for the LumaNotch campaign |
| `app.lumanotch[.]cc` | App subdomain — hosts macOS DMG/PKG installer for the fake LumaNotch utility |
| `smart.lumanotch[.]cc` | Smart/premium tier subdomain — additional delivery endpoint |
| `space.lumanotch[.]cc` | Space edition subdomain — additional delivery endpoint |

### File Hashes

| Hash | Type | Context |
|------|------|---------|
| `5efeda0efe0c7d1bf3e78db272a97a1d305b07ae509c73e27ae3067a188962a8` | SHA256 | Miolab/PamStealer macOS sample associated with LumaNotch campaign (VirusTotal reference) |

### URL Patterns (malicious PHP endpoints on Miolab/PamStealer C2 servers)

| Pattern | Context |
|---------|---------|
| `/niggers.php?debug` | PamStealer/Miolab C2 panel debug endpoint |
| `/niggers.php?files` | C2 exfiltrated file listing endpoint |
| `/niggers.php?metrics` | C2 metrics/reporting endpoint |
| `/niggers.php?scripts` | C2 payload/scripts management endpoint |
| `/niggers.php?swaps` | C2 crypto swap monitoring endpoint |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique | Usage |
|--------|-------------|-----------|-------|
| Initial Access | T1566.002 | Phishing: Spearphishing Link | Victims lured via social media/ads to lumanotch[.]cc to download fake macOS "Dynamic Island" utility |
| Execution | T1204.002 | User Execution: Malicious File | User double-clicks downloaded DMG/PKG to install the fake LumaNotch application |
| Defense Evasion | T1553.002 | Subvert Trust Controls: Code Signing | Samples in prior waves have been notarized with valid Apple Developer IDs to bypass Gatekeeper |
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Name or Location | Malware mimics a legitimate macOS productivity utility (Dynamic Island feature); uses Apple-themed branding |
| Credential Access | T1555.001 | Credentials from Password Stores: Keychain | macOS Keychain enumeration and extraction — primary objective |
| Credential Access | T1555.3 | Credentials from Web Browsers | Browser-stored credentials (Chrome, Firefox, Safari, Brave) extracted |
| Collection | T1005 | Data from Local System | Filesystem enumeration and exfiltration of sensitive files, wallets, seed phrases |
| Collection | T1213 | Data from Information Repositories | Cryptocurrency wallet files targeted (MetaMask, Phantom, Rabby extensions) |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | Exfiltration via HTTP POST to C2 PHP panel |
| Command and Control | T1041 | Exfiltration Over C2 Channel | Encrypted credential archive posted to attacker C2 |

---

## 3. Malware & Tools

**Miolab Stealer / PamStealer / CrashStealer (macOS infostealer)**

This malware family is tracked under multiple names across the threat intelligence community. Maltrail tracks it as `osx_nova` with aliases: **miolab stealer**, **pamstealer**, **crashstealer**. The family has run multiple infrastructure waves (aether/argent/borea wave added 2026-07-30; LumaNotch wave added 2026-08-24 to 2026-08-26).

**LumaNotch campaign specifics:**
- Lure: A fake macOS utility called "LumaNotch" that purports to bring the iPhone's Dynamic Island feature to MacBook (a popular concept in the Mac community)
- The fake app uses Apple-styled marketing pages (`TITLE-HOST` metadata: "LumaNotch – Dynamic Island for macOS", "LumaNotch – Portfolio, Alerts and AI in your MacBook Notch")
- Once installed, the malware collects macOS Keychain credentials, browser-stored passwords and cookies, and cryptocurrency wallet data
- The C2 panel uses a distinctive PHP endpoint pattern (`/niggers.php?<action>`) consistently observed across Miolab/PamStealer campaigns

**Targeting:** Cryptocurrency users and macOS power users seeking productivity utilities. The Dynamic Island lure exploits interest in MacBook customization software, a niche that often involves downloading apps from non-App-Store sources.

**Prior waves tracked in this repo:**
- July 2026 (aether/argent/borea wave): `2026-07-13_jamf-com-crashstealer-macos-c-plus-plus-infostealer.md`
- August 1, 2026 (aether/argent/borea wave): `2026-08-01_maltrail-multi-family-ioc-update-nova-stealer-lumma-donot-hexstresser.md`

---

## 4. Threat Actor / Campaign Attribution

| Attribute | Value |
|-----------|-------|
| Campaign name | LumaNotch (August 2026 wave) |
| Malware family | Miolab Stealer / PamStealer / CrashStealer |
| Attribution | Unattributed; financially motivated; primarily targets cryptocurrency holders |
| Targeting | macOS users; crypto community; productivity app users |
| Distribution | Likely via Google/social media ads, crypto community forums, direct links |
| Prior campaigns | Werkbit (July 2026), aether/argent/borea wave (July 2026), multiple crypto-themed lures |
| Infrastructure pattern | Short-lived lure domains tied to app branding; C2 PHP panels with distinctive endpoint paths |

---

## 5. Splunk Detection Searches

### 1. Network Connection to LumaNotch Campaign Domains (DNS)
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query IN (
    "lumanotch.cc","lumanotch.pro",
    "app.lumanotch.cc","smart.lumanotch.cc","space.lumanotch.cc"
  )
  by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src query answer risk_score
```

### 2. Miolab/PamStealer C2 Panel Endpoint Pattern (Proxy/Web Logs)
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.uri_path IN (
    "/niggers.php",
    "/niggers.php?debug","/niggers.php?files","/niggers.php?metrics",
    "/niggers.php?scripts","/niggers.php?swaps"
  )
  by Web.src Web.dest Web.uri_path Web.http_method Web.status
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src dest uri_path http_method status risk_score
```

### 3. macOS Keychain Access by Non-Apple Process (macOS Endpoint Telemetry)
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process IN ("*security find-generic-password*","*security find-internet-password*",
                               "*SecKeychainItemCopyAttributesAndData*","*security dump-keychain*")
    AND NOT Processes.process_name IN ("Terminal","security","bash","zsh","sh")
  by Processes.dest Processes.user Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=80
| table firstTime lastTime dest user process_name process risk_score
```

### 4. Miolab/PamStealer Known SHA256 Hash Match
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_hash IN (
    "5efeda0efe0c7d1bf3e78db272a97a1d305b07ae509c73e27ae3067a188962a8"
  )
  by Processes.dest Processes.user Processes.process_name Processes.process_hash
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| table firstTime lastTime dest user process_name process_hash risk_score
```

---

## 6. Executive Summary

Threat intelligence sources (Maltrail `osx_nova.txt`, first noted by @L0Psec on X) identified a new August 2026 wave of the Miolab/PamStealer macOS infostealer campaign, this time using a lure themed around "LumaNotch" — a fake macOS utility that purports to bring the iPhone Dynamic Island feature to MacBook Pro notch displays.

The LumaNotch campaign follows the established playbook of the Miolab/PamStealer family: create a convincing macOS productivity app with professional marketing (the lumanotch.cc domain and subdomains use Apple-styled copy), distribute it through advertising or community forums, and once installed, aggressively steal macOS Keychain contents, browser credentials, and cryptocurrency wallet data. The C2 infrastructure uses a distinctive PHP panel endpoint pattern (`/niggers.php?<action>`) that has been consistently observed across multiple Miolab/PamStealer campaigns.

New infrastructure confirmed in this wave (August 24–26, 2026): `lumanotch[.]cc`, `lumanotch[.]pro`, and associated subdomains. The malware sample hash `5efeda0efe0c7d1bf3e78db272a97a1d305b07ae509c73e27ae3067a188962a8` is associated with this wave.

**Analyst action items:**
- Block lumanotch[.]cc and lumanotch[.]pro (and subdomains) at DNS/web proxy
- Alert on `/niggers.php` URI patterns in proxy logs
- Run hash search for the SHA256 in endpoint telemetry
- Advise macOS users against installing unverified macOS utilities from outside the App Store, especially crypto-themed or "Dynamic Island" apps

---

## References

- [Maltrail osx_nova.txt IOC trail](https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/osx_nova.txt)
- [@L0Psec Twitter/X disclosure](https://x.com/L0Psec/status/2079591997610791192)
- [VirusTotal — LumaNotch sample](https://www.virustotal.com/gui/file/5efeda0efe0c7d1bf3e78db272a97a1d305b07ae509c73e27ae3067a188962a8/detection)
- [Jamf CrashStealer report (July 2026)](https://www.jamf.com/blog/crashstealer-macos-infostealer/)
- [MITRE ATT&CK T1555.001 — Credentials from Password Stores: Keychain](https://attack.mitre.org/techniques/T1555/001/)
- [MITRE ATT&CK T1036.005 — Masquerading: Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005/)
