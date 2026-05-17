---
scraped_at: 2026-05-17T00:00:00Z
source_url: https://unit42.paloaltonetworks.com/gremlin-stealer-evolution/
report_type: threat-intel
severity: high
title: "Gremlin Stealer Evolves: Resource File Obfuscation, Crypto Clipping, and Session Hijacking"
---

## 1. IOCs

### File Hashes (SHA-256)

| Hash | Description |
|------|-------------|
| `d1ea7576611623c6a4ad1990ffed562e8981a3aa209717065eddc5be37a76132` | Gremlin Stealer sample — C#-based infostealer with hard-coded Telegram API exfiltration key |
| `2172dae9a5a695e00e0e4609e7db0207d8566d225f7e815fada246ae995c0f9b` | Gremlin Stealer packed variant — single-byte XOR obfuscation over .NET resource section |

### IP Addresses

| IP | Description |
|----|-------------|
| `207.244.199[.]46` | Attacker-controlled C2 and data collection portal — Gremlin Stealer stolen data upload destination; included in sale package for buyers |

### Domains / URLs

No additional domains published. Exfiltration is bot-based via hard-coded Telegram API key pointing to `207.244.199[.]46`.

---

## 2. TTPs

| MITRE Tactic | Technique ID | Technique Name | Usage |
|---|---|---|---|
| Credential Access | T1539 | Steal Web Session Cookie | Browser session cookie theft targeting Chromium and Gecko browsers; circumvents Chrome Cookie V20 defenses |
| Credential Access | T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Chromium/Gecko browser credential extraction including stored usernames, passwords |
| Credential Access | T1552.001 | Unsecured Credentials: Credentials In Files | VPN credential harvesting from config files |
| Credential Access | T1528 | Steal Application Access Token | Telegram session data theft for account takeover |
| Collection | T1115 | Clipboard Data | Clipboard monitoring for crypto wallet addresses; crypto-clipping replaces copied addresses |
| Collection | T1113 | Screen Capture | Screenshot collection and staging |
| Collection | T1005 | Data from Local System | Local device metadata, Steam data, FTP credentials |
| Defense Evasion | T1027.009 | Obfuscated Files or Information: Embedded Payloads | Critical functions decrypted from .NET resource section on demand; prevents static analysis |
| Defense Evasion | T1027.002 | Obfuscated Files or Information: Software Packing | Packing utility applied to samples; XOR-based decryption of resource payloads |
| Exfiltration | T1567 | Exfiltration Over Web Service | Stolen data exfiltrated via Telegram Bot API to attacker-controlled portal |
| Impact | T1565.001 | Data Manipulation: Stored Data Manipulation | Crypto-clipping: replaces clipboard cryptocurrency wallet addresses with attacker-controlled addresses |

---

## 3. Malware & Tools

### Gremlin Stealer (evolved)

Gremlin Stealer is a C#-based Windows infostealer first advertised on Telegram channel "CoderSharp" in March 2025 and sold as Malware-as-a-Service (MaaS). The May 2026 Unit 42 analysis documents a significant evolution in obfuscation and modular capability:

**Obfuscation — Resource File Staging**
Each critical function is stored encrypted within the .NET resource section. Functions are decrypted and mapped into memory via single-byte XOR only at the moment of execution, forcing analysts to conduct live dynamic debugging rather than static analysis. This staged loading mechanism is the primary anti-analysis innovation.

**Credential Theft**
- Chromium-based and Gecko-based browser credential stores, cookies, and saved passwords
- Chrome Cookie V20 defense circumvented
- VPN credential files
- Steam session data
- FTP service credentials

**Crypto Targeting**
- Clipboard monitoring with wallet address replacement (crypto clipping)
- Cryptocurrency wallet data exfiltration

**Messaging Platform Targeting**
- Telegram session data theft

**Exfiltration**
- Hard-coded Telegram Bot API key used to POST stolen data
- Data uploaded to attacker-controlled portal at `207.244.199[.]46`
- Portal is part of the MaaS package provided to buyers, allowing centralized victim data management

---

## 4. Threat Actor / Campaign Attribution

| Attribute | Value |
|---|---|
| Malware Family | Gremlin Stealer |
| Distribution | Telegram MaaS — channel "CoderSharp" |
| Developer | Unknown; .NET/C# developer active since at least March 2025 |
| Targeting | Windows endpoints; cryptocurrency users; corporate employees with browser-stored credentials |
| Associated Variants | SHub Stealer (separate actor selling modified Gremlin source code) |

Gremlin Stealer is sold to multiple threat actors as a MaaS offering. No single state-sponsored group is attributed; buyers are varied cybercriminal actors.

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_ip="207.244.199.46"
  by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src_ip dest_ip dest_port app risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process IN ("*api.telegram.org*","*bot*sendDocument*","*bot*sendMessage*")
    AND NOT Processes.process_name IN ("chrome.exe","firefox.exe","msedge.exe","slack.exe","teams.exe")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process,"(?i)sendDocument"), 90,
    match(process,"(?i)sendMessage"), 80,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path IN ("*\\AppData\\Local\\*\\User Data\\Default\\Login Data*",
                                  "*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*\\logins.json*",
                                  "*\\AppData\\Roaming\\Telegram Desktop\\tdata\\*",
                                  "*\\AppData\\Local\\Steam\\config\\loginusers.vdf*")
    AND Filesystem.action="read"
  by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_path,"(?i)Login Data") AND NOT match(process_name,"(?i)chrome|msedge|brave"), 90,
    match(file_path,"(?i)logins\.json") AND NOT match(process_name,"(?i)firefox"), 90,
    match(file_path,"(?i)Telegram.*tdata"), 85,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user process_name file_path risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where (Filesystem.file_hash="d1ea7576611623c6a4ad1990ffed562e8981a3aa209717065eddc5be37a76132"
      OR Filesystem.file_hash="2172dae9a5a695e00e0e4609e7db0207d8566d225f7e815fada246ae995c0f9b")
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.file_hash
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest user file_path file_name file_hash risk_score
```

---

## 6. Executive Summary

On May 15, 2026, Unit 42 published an analysis of the latest Gremlin Stealer variant, documenting significant evolution in obfuscation tradecraft. Gremlin Stealer is a C#-based Windows infostealer sold via Telegram as Malware-as-a-Service since March 2025. The evolved variant moves away from static payloads to a resource-file staging model where each critical function is stored in the .NET resource section in single-byte XOR-encrypted form and only decrypted into memory at execution time.

The stealer targets a broad range of credentials: Chromium and Gecko browser stores (including Chrome Cookie V20 bypass), Telegram session files, Steam data, FTP credentials, and VPN configs. A crypto-clipping module monitors and replaces clipboard wallet addresses in real time. All data is exfiltrated via a hard-coded Telegram Bot API key to an attacker-controlled portal at `207.244.199[.]46`.

Two sample hashes and one C2 IP are confirmed new IOCs. Detection focus: anomalous access to browser credential store files from non-browser processes, outbound connections to `207.244.199[.]46`, and non-browser processes communicating with the Telegram Bot API.
