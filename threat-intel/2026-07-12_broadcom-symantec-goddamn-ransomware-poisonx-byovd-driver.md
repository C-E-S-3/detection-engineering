---
scraped_at: 2026-07-12T00:00:00Z
source_url: https://www.security.com/threat-intelligence/goddamn-ransomware-beast-rebrand
report_type: threat-intel
severity: high
title: "GodDamn Ransomware (Hyadina RaaS): Beast Rebrand with PoisonX BYOVD Kernel Driver"
tags:
  - ransomware
  - byovd
  - hyadina
  - goddamn
  - T1486
  - T1543.003
  - T1562.001
---

# GodDamn Ransomware (Hyadina RaaS): Beast Rebrand with PoisonX BYOVD Kernel Driver

**Source:** [Broadcom / Symantec Threat Intelligence — GodDamn Ransomware](https://www.security.com/threat-intelligence/goddamn-ransomware-beast-rebrand)  
**Reported:** 2026-07-09  
**Severity:** High  

---

## Summary

GodDamn is a new ransomware-as-a-service (RaaS) family operated by the **Hyadina** group, confirmed as a rebrand of the Beast ransomware lineage (Monster 2022 → Beast → GodDamn). Hyadina operators deploy a custom BYOVD (Bring Your Own Vulnerable Driver) tool called **PoisonX** to kill endpoint detection and response tools before encryption. PoisonX drops a Microsoft-signed kernel driver (`g11.sys`) authored by GitHub user "oxfemale" into the Windows driver store, then issues IOCTL calls to terminate security processes at ring 0. After EDR impairment, ransomware encryption targets files appending the `.God8Damn` extension (some victims report victim-specific extensions). Initial access is via AnyDesk remote desktop installation; lateral movement uses PsExec; credential theft uses the NirSoft toolkit. Extortion is conducted out-of-band via qTox and email — no ransom note is dropped on disk.

---

## Threat Actor: Hyadina

| Field | Value |
|-------|-------|
| Name | Hyadina |
| Type | Ransomware-as-a-Service (RaaS) operator |
| Lineage | Monster (2022) → Beast → GodDamn (2026) |
| Operation | Double extortion (data leak + encryption) |
| Contact | qTox + email (out-of-band, no on-disk ransom note) |
| Encrypted extension | `.God8Damn` (may be victim-specific in some deployments) |

---

## Attack Chain

1. **Initial Access**: AnyDesk installed on target (social engineering or compromised credentials).
2. **Credential Theft**: NirSoft toolkit (e.g., `WebBrowserPassView`, `MailPassView`) extracts credentials from browsers and email clients.
3. **BYOVD — EDR Impairment**: `symantec.exe` (impersonates a Symantec process name) drops `g11.sys` into the Windows driver store and registers it as a kernel driver service.
4. **EDR Kill**: PoisonX issues IOCTLs to the loaded `g11.sys` driver to terminate EDR processes at kernel level, bypassing user-mode tamper protection.
5. **Lateral Movement**: PsExec used to spread to additional hosts on the network.
6. **Data Exfiltration**: Sensitive files exfiltrated prior to encryption (double extortion).
7. **Encryption**: GodDamn encryptor runs, appending `.God8Damn` extension; no ransom note dropped on disk.
8. **Extortion**: Hyadina contacts victim via qTox and email, threatening to publish stolen data.

---

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Defense Evasion, Impact |
| Technique | T1543.003 — Create or Modify System Process: Windows Service (driver registration) |
| Technique | T1562.001 — Impair Defenses: Disable or Modify Tools (BYOVD EDR kill) |
| Technique | T1486 — Data Encrypted for Impact |
| Technique | T1078 — Valid Accounts (AnyDesk, compromised credentials) |
| Technique | T1570 — Lateral Tool Transfer (PsExec) |
| Technique | T1555.003 — Credentials from Web Browsers (NirSoft) |
| Technique | T1036.005 — Masquerading: Match Legitimate Name or Location (symantec.exe dropper) |

---

## IOCs

### File Hashes (SHA256)

| Hash | Description |
|------|-------------|
| `2d91a78e739891c9854c254f5b2a6b84c0e167dfa253466cbccd2cdd1c20145d` | PoisonX kernel driver `g11.sys` — Microsoft-signed BYOVD driver; driver store installation by `symantec.exe` dropper; author: GitHub "oxfemale" |

### Artifacts

| Artifact | Description |
|----------|-------------|
| `symantec.exe` | PoisonX dropper; impersonates Symantec process name; drops `g11.sys` into driver store |
| `g11.sys` | Vulnerable/malicious Microsoft-signed kernel driver; accepts IOCTLs to terminate arbitrary processes at ring 0 |
| `.God8Damn` | Encrypted file extension appended by GodDamn ransomware |

### Infrastructure

AnyDesk relay infrastructure used for initial access is shared with legitimate AnyDesk users and should not be added to network blocklists. No dedicated C2 IPs identified.

---

## Detection Notes

Existing BYOVD detections in this repository cover PoisonX generically:

- **[BYOVD Vulnerable Driver Loading](../detections/defense_evasion/byovd_vulnerable_driver_loading.md)**: The SHA256 hash `2d91a78e739891c9854c254f5b2a6b84c0e167dfa253466cbccd2cdd1c20145d` for `g11.sys` should be added to the Splunk `byovd_driver_hashes` lookup table.
- **[BYOVD Kernel Driver Service Creation](../detections/defense_evasion/byovd_driver_service_creation.md)**: `symantec.exe` creating a new kernel driver service is a high-confidence indicator.
- **[BYOVD Security Tool Process Termination](../detections/defense_evasion/byovd_security_tool_termination.md)**: Rapid EDR process termination following `g11.sys` load.

The `symantec.exe` filename masquerade (a non-Symantec process attempting to load a kernel driver service) is an especially high-confidence indicator given the impersonation of a security vendor.

---

## References

- [Broadcom / Symantec — GodDamn Ransomware (Beast Rebrand)](https://www.security.com/threat-intelligence/goddamn-ransomware-beast-rebrand)
- [MITRE ATT&CK — T1543.003 Windows Service](https://attack.mitre.org/techniques/T1543/003/)
- [MITRE ATT&CK — T1562.001 Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
- [MITRE ATT&CK — T1486 Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
