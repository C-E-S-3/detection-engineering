---
scraped_at: 2026-06-24T00:00:00Z
source_url: multiple — see references
report_type: threat-intel-batch
severity: high
title: "Wazuh Rules Batch: Prinz Eugen Ransomware + CryptoBandits USB Worm + WhatsApp VBScript RMM + QUIETVAULT AI Stealer + GreatXML BitLocker Bypass + BRICKSTORM Appliance Backdoor (2026-06-24)"
---

## Summary

Detection rules (Wazuh XML, IDs 103496–103540) for six high-severity threat intelligence items from the 2026-06-22/23 threat-intel-routine commits and M-Trends 2026. Rules cover Windows, Linux, and network appliance syslog detection surfaces.

## Threats Covered

### 1. Prinz Eugen Ransomware (ROOTBOY) — Rules 103496–103502

Go-based ransomware (RaaS) that prioritizes recently modified files for encryption, drops no ransom note, and performs out-of-band extortion. Initial access via compromised RDP credentials.

**Key IOCs:** `.prinzeugen` file extension, `servertool.exe` dropper binary, `CHV1` file header magic.

**TTPs:** T1486 (Data Encrypted for Impact), T1070.004 (File Deletion), T1489 (Service Stop), T1078 (Valid Accounts), T1036.005 (Masquerading).

**Attribution:** ROOTBOY (Russian-language forums Exploit/DarkForums); first victim Standard Bank Group (South Africa, April 2026).

### 2. CryptoBandits USB LNK Worm + Tor Crypto Clipper — Rules 103503–103511

USB worm spreading via malicious LNK shortcuts that replace legitimate documents. Deploys Tor proxy (`ugate.exe`) for C2 via .onion addresses. Polls clipboard for crypto wallet addresses.

**Key IOCs:** `ugate.exe` (renamed Tor binary), `C:\Users\Public\Documents\[5char]\[5char].js` staging path, SOCKS5 on localhost:9050.

**TTPs:** T1091 (USB Replication), T1059.007 (JavaScript), T1053.005 (Scheduled Task), T1090.003 (Tor proxy), T1562.001 (Defender exclusion), T1115 (Clipboard Data).

### 3. WhatsApp VBScript / ManageEngine RMM Campaign — Rules 103512–103519

Chinese-linked actor distributes obfuscated VBScript via WhatsApp (as fake business docs). Bypasses UAC via HKCU registry, then deploys ManageEngine Endpoint Central as persistent backdoor.

**Key IOCs:** C2 IP `202.61.160.201` (ValleyRAT/Gh0st RAT infra overlap).

**TTPs:** T1566.004 (Phishing via WhatsApp), T1059.005 (VBScript), T1548.002 (UAC bypass ms-settings), T1219 (RMM abuse), T1105 (Tool Transfer).

### 4. QUIETVAULT AI-Assisted Credential Stealer — Rules 103520–103526

Novel stealer (M-Trends 2026) that uses locally-installed AI CLI tools (Ollama, llm, GPT4All) to enumerate and access credential files at runtime, avoiding static signatures.

**TTPs:** T1552.001 (Credentials in Files), T1083 (File Discovery), T1059.001 (PowerShell).

### 5. GreatXML WinRE / BitLocker Bypass PoC — Rules 103527–103532

Zero-day PoC (Nightmare Eclipse, June 22 2026) that abuses WinRE answer files and Windows Defender Offline Scan state to spawn a SYSTEM shell on BitLocker-protected devices. Physical access required. No CVE assigned.

**TTPs:** T1542.001 (Pre-OS Boot: System Firmware), T1059.003 (Windows Command Shell).

**Note:** inframan PR may be needed to enable monitoring of `Autounattend.xml` via Wazuh FIM config if not already in scope.

### 6. BRICKSTORM In-Memory Network Appliance Backdoor — Rules 103533–103540

Chinese-nexus (UNC6201/UNC5807) custom implant targeting edge network appliances (Ivanti, Fortinet, Cisco). Lives entirely in memory; detected via syslog shell command patterns forwarded to Wazuh.

**TTPs:** T1505.003 (Web Shell), T1040 (Network Sniffing), T1059 (Scripting), T1027.011 (Fileless Storage).

**Requirement:** OPNsense/network device syslog must be forwarded to Wazuh (`/var/ossec/etc/ossec.conf` remote syslog or Wazuh agent on firewall). Hostnames must match `opnsense|pfsense|fortinet|cisco|asa|fortigate|ivanti` pattern in rule 103533.

## Rule IDs

| Range | Threat |
|-------|--------|
| 103496–103502 | Prinz Eugen Ransomware |
| 103503–103511 | CryptoBandits USB Worm |
| 103512–103519 | WhatsApp VBScript/ManageEngine RMM |
| 103520–103526 | QUIETVAULT AI Credential Stealer |
| 103527–103532 | GreatXML WinRE BitLocker Bypass |
| 103533–103540 | BRICKSTORM Network Appliance Backdoor |

**Next available rule ID:** 103541

## IOCs Added

No IOC CSV updates needed — IOCs for these reports were already added to `iocs/ip.csv` and `iocs/hash.csv` by the threat-intel-routine in commits 594e68a and 3743966.

## References

- [BleepingComputer — Prinz Eugen ransomware (2026-06-20)](https://www.bleepingcomputer.com/news/security/new-prinz-eugen-ransomware-prioritizes-recent-files-for-encryption/)
- [Microsoft Security Blog — CryptoBandits (2026-06-17)](https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/)
- [Kaspersky Securelist — WhatsApp VBScript/ManageEngine (2026-06-22)](https://securelist.com/whatsapp-vbs-rmm-campaign/120290/)
- [M-Trends 2026 — QUIETVAULT AI-assisted credential stealer](https://www.mandiant.com/m-trends)
- [SecurityWeek — GreatXML PoC (2026-06-22)](https://www.securityweek.com/greatxml-zero-day-exploit-bypasses-bitlocker/)
- [BRICKSTORM UNC6201/UNC5807 network appliance implant](https://cloud.google.com/blog/topics/threat-intelligence/brickstorm-network-appliance-implant/)
