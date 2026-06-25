---
scraped_at: 2026-06-20T00:00:00Z
source_url: https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/
report_type: threat-intel
severity: high
title: "Windows USB LNK Crypto Clipper Worm with Tor-Based C2 (T1091/T1115/T1090.003)"
---

## 1. IOCs

### Domains
No traditional C2 domains — C2 operated via Tor hidden service (.onion); not publicly disclosed.

### IP Addresses
None (Tor-based C2 prevents attribution via IP).

### File Hashes
Not publicly released.

### Other
- Initial access vector: Malicious `.lnk` shortcut files on USB storage devices
- C2 protocol: Tor SOCKS5 proxy on localhost (bundled Tor client); connects to hidden service
- Clipboard poll interval: ~500ms
- Active since: February 2026
- Target: Windows users with cryptocurrency wallets (BTC, ETH, BIP39 seed phrases)

---

## 2. TTPs

| Tactic | Technique ID | Technique | Usage |
|--------|-------------|-----------|-------|
| Initial Access | T1091 | Replication Through Removable Media | .lnk (Windows Shortcut) files on USB drives; Explorer auto-processes .lnk on mount |
| Execution | T1204.002 | User Execution: Malicious File | User browses USB drive in Explorer; .lnk file triggers wscript.exe / ActiveX |
| Execution | T1059.005 | Command and Scripting Interpreter: Visual Basic | Windows Script Host (wscript.exe) executes embedded VBS logic from .lnk file |
| Command & Control | T1090.003 | Proxy: Multi-hop Proxy | Bundled portable Tor client routes all C2 traffic through Tor network |
| Command & Control | T1071.001 | Application Layer Protocol: Web Protocols | C2 polling over SOCKS5 proxy to .onion hidden service |
| Collection | T1115 | Clipboard Data | Clipboard monitored every 500ms; cryptocurrency addresses replaced with attacker-controlled addresses |
| Collection | T1552.001 | Unsecured Credentials: Credentials In Files | Searches for BIP39 seed phrases, Ethereum private keys, Bitcoin WIF keys in filesystem |
| Persistence | T1053.005 | Scheduled Task/Job: Scheduled Task | Malware creates scheduled task for persistence on reboots |
| Defense Evasion | T1027 | Obfuscated Files or Information | Payload obfuscated; Tor client bundled to avoid network-layer detection |
| Lateral Movement | T1091 | Replication Through Removable Media | Worm propagates by copying .lnk files to all connected USB storage |

---

## 3. Malware & Tools

| Malware | Type | Notes |
|---------|------|-------|
| USB LNK Clipper | Cryptocurrency clipboard hijacker + worm | Active since February 2026; targets BTC/ETH wallet addresses and BIP39 seed phrases; polls clipboard 2×/second; routes all C2 via bundled Tor client; worm spreads via USB |
| Bundled Tor client | Anonymization proxy | Portable Tor binary bundled with payload; creates local SOCKS5 proxy for C2 and screenshot exfil |

---

## 4. Threat Actor / Campaign Attribution

- **Threat Actor**: Unattributed financially motivated actor; Russian-speaking communities suspected (clipboard-clipping campaigns historically linked to CIS-based actors)
- **Discovery**: June 17, 2026 (Microsoft Security Blog)
- **Campaign Duration**: February 2026 – present (4+ months active)
- **Scale**: Not disclosed by Microsoft; targets appear to be individual cryptocurrency users
- **Attribution confidence**: Low — Tor C2 prevents infrastructure-based attribution; TTP overlap with known clipboard-clipping malware families from Eastern Europe

---

## 5. Splunk Detection Searches

```spl
| comment "USB LNK Clipper Worm: Detect Windows Script Host processing .lnk files from removable media"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("wscript.exe", "cscript.exe", "mshta.exe")
    AND (Processes.parent_process_name="explorer.exe"
      OR Processes.process LIKE "%\\Users\\%\\AppData\\Local\\Temp%"
      OR Processes.process LIKE "%.lnk%")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "\.lnk"), 85,
    match(process, "\\\\[EFG-Z]:\\\\"), 80,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| comment "USB LNK Clipper Worm: Detect Tor client process spawned from non-browser parent (bundled Tor in malware)"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name="tor.exe"
    AND NOT Processes.parent_process_name IN ("firefox.exe", "tor-browser.exe", "start-tor-browser.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user parent_process_name process_name process_path risk_score
```

```spl
| comment "USB LNK Clipper Worm: Detect outbound SOCKS5 traffic to localhost:9050/9150 (Tor proxy activation)"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_ip="127.0.0.1"
    AND All_Traffic.dest_port IN (9050, 9150)
    AND NOT All_Traffic.app IN ("tor", "firefox", "brave", "vidalia")
  by All_Traffic.src All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app All_Traffic.process_id
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime src dest_ip dest_port app process_id risk_score
```

```spl
| comment "USB LNK Clipper Worm: Detect LNK files written to removable media (worm propagation)"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_name LIKE "*.lnk"
    AND (Filesystem.file_path LIKE "%:\\Users\\%\\AppData\\Roaming%"
      OR Filesystem.file_path LIKE "%:\\Users\\%\\AppData\\Local%")
    AND Filesystem.action="created"
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| table firstTime lastTime dest user file_path file_name risk_score
```

---

## 6. Executive Summary

Microsoft disclosed on June 17, 2026 a Windows cryptocurrency clipper campaign active since February 2026. The malware spreads via malicious `.lnk` shortcut files placed on USB storage devices. When an infected drive is connected to a Windows system and browsed in Explorer, the .lnk file automatically triggers Windows Script Host (wscript.exe) with embedded VBScript logic.

The malware deploys a **bundled portable Tor client** to route C2 communications through the Tor anonymity network, eliminating the traditional reliance on exposed C2 IP addresses or domains that would allow blocking at the network perimeter. The malware polls the clipboard every 500ms, replacing any cryptocurrency wallet addresses (Bitcoin, Ethereum) or BIP39 seed phrases with attacker-controlled equivalents — silently redirecting any crypto transfer to the attacker.

The worm capability copies .lnk files to any connected USB storage, enabling victim-driven spreading through USB sharing. Persistence is achieved via scheduled tasks. The combination of Tor C2, worm propagation, and high-frequency clipboard monitoring makes this particularly resilient against standard countermeasures.

**Recommended actions**: Disable Windows Script Host (wscript.exe/cscript.exe) via Group Policy on non-developer systems; block Tor client execution via application control policy (AppLocker/WDAC); monitor for non-browser processes connecting to localhost:9050/9150 (Tor SOCKS port); alert on Explorer spawning wscript.exe; audit scheduled tasks created by non-admin users.
