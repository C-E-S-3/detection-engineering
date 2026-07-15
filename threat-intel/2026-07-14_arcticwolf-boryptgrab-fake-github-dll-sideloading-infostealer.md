---
scraped_at: 2026-07-15T00:00:00Z
source_url: https://arcticwolf.com/resources/blog/fake-github-repositories-deliver-boryptgrab-lineage-infostealer/
report_type: threat-intel
severity: high
title: "BoryptGrab Infostealer Distributed via 292+ Fake GitHub Repositories Using WinGUP.exe DLL Sideloading"
---

## 1. IOCs

No specific IOC values confirmed at time of reporting (source infrastructure returned HTTP 403 during fetch attempts). IOC list should be updated when Arctic Wolf or Trend Micro publish their full indicator sets.

---

## 2. Summary

A large-scale infostealer campaign distributing BoryptGrab (also tracked as part of the BoryptGrab lineage alongside HeaconLoad, TunnesshClient, and Vidar) was disclosed by Arctic Wolf and Trend Micro in mid-July 2026. The campaign uses a network of 292+ brand-impersonating GitHub repositories active since approximately June 26, 2026, to distribute malicious archives that abuse DLL sideloading via the legitimate Notepad++ updater binary WinGUP.exe.

---

## 3. Malware and Techniques

### Distribution

- **292+ fake GitHub repositories** impersonating popular software brands and tools
- Campaign active since approximately June 26, 2026
- Archives distributed from these repositories contain a signed legitimate binary alongside a malicious DLL

### DLL Sideloading Chain

| Component | Description |
|-----------|-------------|
| `WinGUP.exe` | Legitimate, signed Notepad++ auto-updater binary (GUP — Generic Updater). Used as a trusted host for DLL sideloading. |
| `libcurl.dll` | Malicious DLL placed in the same directory as WinGUP.exe. Loaded automatically when WinGUP.exe starts due to DLL search order. |

When executed, `WinGUP.exe` loads `libcurl.dll` from its current working directory before checking System32, allowing the attacker-controlled DLL to run within the context of the signed binary.

### In-Memory Loader

- Malicious `libcurl.dll` uses **COM/SafeArray staging** for reflective in-memory loading
- Payload is loaded entirely in memory with no additional on-disk artifacts beyond the initial two files
- Technique provides anti-analysis and anti-forensic properties

### Data Theft Capabilities

BoryptGrab targets:
- **41 cryptocurrency wallet types** (browser extensions, desktop wallets)
- **19+ web browsers** (credentials, cookies, saved passwords, autofill data)
- Messaging applications
- Data exfiltrated as an encrypted ZIP archive to a Russian-hosted C2 server

### Related Malware

| Malware | Relationship |
|---------|-------------|
| HeaconLoad | Related loader in the BoryptGrab lineage |
| TunnesshClient | Related C2 communication component |
| Vidar | Related infostealer; shared infrastructure or code components |

---

## 4. MITRE ATT&CK

| Tactic | Tactic ID | Technique | Technique ID |
|--------|-----------|-----------|-------------|
| Initial Access | TA0001 | Drive-by Compromise | T1189 |
| Defense Evasion | TA0005 | Hijack Execution Flow: DLL Side-Loading | T1574.002 |
| Collection | TA0009 | Data from Local System | T1005 |
| Exfiltration | TA0010 | Exfiltration Over C2 Channel | T1041 |
| Credential Access | TA0006 | Credentials from Password Stores: Credentials from Web Browsers | T1555.003 |

---

## 5. Kill Chain Phase

Delivery → Exploitation → Installation → Actions on Objectives

---

## 6. Threat Actor Assessment

No specific threat actor attribution at time of reporting. Campaign characteristics (fake repository network, Russian-hosted C2, cryptocurrency targeting, Vidar codebase overlap) are consistent with financially motivated Eastern European cybercriminal groups. The Vidar connection suggests possible involvement with the same ecosystem as Vidar's MaaS operators.

---

## 7. Detection Guidance

- Alert on `WinGUP.exe` executing from any path outside `%ProgramFiles%\Notepad++\updater\` or `%ProgramFiles(x86)%\Notepad++\updater\`
- Alert on `WinGUP.exe` spawned by browser processes, archive extraction tools (7-Zip, WinRAR), or other unexpected parents
- Alert on `libcurl.dll` loaded from user-writable paths (Temp, AppData, Downloads, Public, ProgramData)
- Hunt for COM/SafeArray-based reflective loading patterns in memory analysis
- Block GitHub repository downloads of password-protected archives that contain paired signed EXE + DLL

---

## 8. References

- [Arctic Wolf — Fake GitHub Repositories Deliver BoryptGrab Lineage Infostealer (2026-07-14)](https://arcticwolf.com/resources/blog/fake-github-repositories-deliver-boryptgrab-lineage-infostealer/)
- [Trend Micro — BoryptGrab Infostealer IOC report (2026-07-14)](https://www.trendmicro.com/en_us/research/)
- [BleepingComputer — BoryptGrab Infostealer Fake GitHub Campaign (2026-07-14)](https://www.bleepingcomputer.com/news/security/)
- [MITRE ATT&CK T1574.002 — DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/)
