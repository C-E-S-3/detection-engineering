---
scraped_at: 2026-08-11T00:00:00Z
source_url: https://raw.githubusercontent.com/PaloAltoNetworks/Unit42-timely-threat-intel/main/2026-08-06-Obfuscated-JavaScript-Crypto-Stealer.txt
report_type: threat-intel
severity: high
title: "Unit 42: Obfuscated JavaScript npm Crypto Stealer — Browser Credentials & Wallet Exfiltration (2026-08-06)"
---

# Unit 42: Obfuscated JavaScript npm Crypto Stealer

## Executive Summary

Palo Alto Networks Unit 42 disclosed an active supply chain campaign involving 10 malicious npm packages published between 2026-07-18 and 2026-07-22. The packages install an obfuscated JavaScript payload that functions as a combined crypto wallet stealer and Remote Access Trojan (RAT). The malware targets browser-stored credentials (Chrome, Brave, Opera, Yandex, Edge), crypto wallet browser extensions, desktop wallet application files (Exodus, Guarda, Electrum, Atomic), environment files, and macOS/Linux keychain data. Stolen data is exfiltrated to attacker-controlled C2 infrastructure over HTTPS on port 45000. The attacker-controlled domain `bet.slotgambit[.]com` serves as an additional payload delivery endpoint. No threat actor attribution was provided by Unit 42 in this disclosure. The campaign file was originally published 2026-08-06 and updated 2026-08-10 with additional C2 infrastructure.

---

## IOCs

### IP Addresses

| IP | Port | Role |
|----|------|------|
| 31.97.137.157 | 45000 | Payload download server |
| 46.183.25.232 | 45000 | Payload download server / primary C2 |

### Domains

| Domain | Role |
|--------|------|
| bet.slotgambit[.]com | Payload delivery domain |

### File Hashes

| Hash | Type | Description |
|------|------|-------------|
| 6d585d11236277c42bf3666192f89733b1d5595967f6434a2e1b6c9d8584a22c | SHA256 | JSON document container (initial payload stage) |
| f591ececf07aedf2f60dc9a362033b6f718799d5909ab38b6941a5296555532b | SHA256 | Malicious JavaScript payload (stealer/RAT) |

---

## Targeted Applications

**Browsers (credential theft):**
- Google Chrome
- Brave
- Opera
- Yandex Browser
- Microsoft Edge

**Crypto Wallets (browser extensions + desktop):**
- Exodus
- Guarda
- Electrum
- Atomic Wallet

**Other:**
- `.env` files (secrets, API keys)
- Keyword-matched files on the filesystem
- macOS Keychain / Linux Secret Service credential stores

---

## Malware Capabilities & TTPs

| Capability | Detail |
|------------|--------|
| Supply chain delivery | 10 malicious npm packages published to npmjs.com registry (2026-07-18 to 2026-07-22) |
| Payload obfuscation | JavaScript obfuscation to evade static analysis |
| Browser credential theft | Exfiltrates saved passwords and session cookies from Chromium-based browsers |
| Crypto wallet harvesting | Targets browser extension wallets and desktop wallet data files |
| Environment variable theft | Reads and exfiltrates `.env` files containing API keys and secrets |
| Keychain access | Accesses macOS Keychain and Linux credential stores |
| RAT functionality | Accepts C2-directed commands and facilitates on-demand file transfers |
| HTTPS C2 on non-standard port | Communicates to 46.183.25.232:45000 and 31.97.137.157:45000 over HTTPS |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Sub-technique | Description |
|--------|-----------|---------------|-------------|
| Initial Access | T1195 | T1195.002 | Compromise Software Supply Chain — malicious npm packages |
| Credential Access | T1555 | T1555.003 | Credentials from Web Browsers — Chrome/Brave/Opera/Yandex/Edge |
| Credential Access | T1555 | T1555.001 | Keychain — macOS Keychain access |
| Collection | T1005 | | Data from Local System — wallet files, .env, keyword-matched files |
| Collection | T1087 | | Account Discovery — wallet extension and account enumeration |
| Exfiltration | T1041 | | Exfiltration Over C2 Channel — HTTPS POST to port 45000 |
| Command and Control | T1071 | T1071.001 | Application Layer Protocol: Web Protocols — HTTPS C2 |
| Command and Control | T1571 | | Non-Standard Port — C2 over port 45000 |
| Defense Evasion | T1027 | | Obfuscated Files or Information — JavaScript obfuscation |

---

## Threat Actor Attribution

No attribution provided by Unit 42. The campaign overlaps in technique with other DPRK-linked Contagious Interview supply chain attacks (npm packages targeting crypto wallet users) but no explicit attribution was made. The `slotgambit[.]com` domain does not match known threat actor infrastructure in public reporting.

---

## Detection & Hunting Opportunities

### npm Package Registry Monitoring

Organizations using npm should monitor for packages installed from accounts with minimal history. The 10 packages in this campaign were published in a 4-day window (2026-07-18 to 2026-07-22), consistent with throwaway publisher accounts.

### Network-Based Detection

Outbound HTTPS to port 45000 is highly anomalous for developer workstations and CI/CD pipelines. This should be blocked and alerted on at the firewall/proxy level.

### Host-Based Detection

Processes spawned from Node.js or npm postinstall hooks accessing browser profile directories (`AppData\Local\Google\Chrome\User Data`, `Library/Application Support/Google/Chrome`) or wallet data directories are strong indicators of compromise.

### Splunk Detection Searches

**1. Outbound HTTPS to non-standard port 45000:**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_port=45000 All_Traffic.app=ssl
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.bytes_out
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table src dest dest_port bytes_out firstTime lastTime count
```

**2. npm postinstall process accessing browser credential paths:**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("node.exe","node","npm","npm.cmd")
    Processes.process IN ("*User Data*","*Login Data*","*Exodus*","*Atomic*","*Electrum*","*Guarda*","*.env*")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table dest user parent_process_name process_name process firstTime lastTime count
```

**3. Known C2 IP connectivity:**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest IN ("31.97.137.157","46.183.25.232")
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table src dest dest_port firstTime lastTime count
```

---

## Associated Threat Actors

No confirmed attribution. Techniques overlap with:

- **Lazarus Group / Contagious Interview (UNC4899 / DPRK)** — MITRE G0032 — npm supply chain campaigns targeting crypto developers; [MITRE ATT&CK](https://attack.mitre.org/groups/G0032/)
- **CL-STA-0240** — Unit 42 cluster for npm-based crypto stealer activity

---

## References

- [Unit 42 Timely Threat Intel: Obfuscated JavaScript Crypto Stealer (2026-08-06)](https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2026-08-06-Obfuscated-JavaScript-Crypto-Stealer.txt)
- [MITRE ATT&CK T1195.002: Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/002/)
- [MITRE ATT&CK T1555.003: Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/)
- [Related: Unit 42 Multi-Actor npm/PyPI Supply Chain (July 2026)](https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2026-07-10-Malicious-NPM-Packages.txt)
