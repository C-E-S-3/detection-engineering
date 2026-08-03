---
scraped_at: 2026-08-03T06:00:00Z
source_url: https://securelist.com/octlurk-silklurk-backdoors-central-asia/120840/
report_type: threat-intel
severity: high
title: "OctLurk & SilkLurk: Memory-Resident Backdoors Targeting Central Asian Government Entities"
---

# OctLurk & SilkLurk — Central Asian Government Espionage Campaign

**Source:** Kaspersky Securelist  
**Published:** 2026-07-31  
**Severity:** High  

## Summary

Kaspersky published research on 2026-07-31 documenting two previously undocumented backdoors — **OctLurk** and **SilkLurk** — deployed against government and public-sector organizations across Central Asia and Syria. The campaign has been active since at least January 2025 and is attributed to a Chinese-speaking threat actor based on code artifacts and targeting profile.

Both implants are memory-resident, significantly reducing their forensic footprint. The campaign demonstrates sustained, stealthy access operations consistent with state-sponsored intelligence collection against Central Asian government ministries, law enforcement, healthcare, research, logistics, and education institutions.

## Technical Details

### OctLurk

OctLurk is a modular, memory-resident backdoor with the following capabilities:

- **Keylogging** — captures all keystrokes in real time
- **Browser credential theft** — extracts saved passwords from major browsers
- **Email collection** — harvests mailbox contents
- **Remote command execution** — executes attacker-supplied commands
- **Plugin injection** — loads additional capability modules in memory at runtime

OctLurk communicates with C2 infrastructure using encrypted channels and maintains no persistent on-disk payload beyond the initial dropper stage.

### SilkLurk

SilkLurk is a companion implant with complementary capabilities:

- **DLL side-loading** — abuses legitimate signed binaries to load the malicious DLL
- **Victim-computer-name-based decryption** — payload decryption key is derived from the victim's computer name, preventing sandbox analysis
- **Memory injection** — injects into legitimate host processes to evade detection
- **Service persistence** — installs as a Windows service for persistence across reboots

## Targeting

- **Geography:** Afghanistan, Kazakhstan, Kyrgyzstan, Tajikistan, Uzbekistan, Syria
- **Sectors:** Government ministries, law enforcement agencies, healthcare organizations, academic/research institutions, logistics companies, educational institutions
- **Active Since:** January 2025
- **Attribution:** Chinese-speaking threat actor (based on code artifacts, operator tooling, and targeting profile; no formal group name assigned)

## IOCs

### Domains

| Indicator | Type | Context |
|-----------|------|---------|
| `dns.multitoconference[.]com` | Domain | OctLurk/SilkLurk C2 infrastructure |
| `tj.tajikistandip[.]com` | Domain | OctLurk/SilkLurk C2 infrastructure (Tajikistan-themed lure domain) |

### Hashes

| Indicator | Type | Context |
|-----------|------|---------|
| `082d49ef9f14e6811d68c7e0e82e5069` | MD5 | OctLurk dropper/loader sample |

## MITRE ATT&CK TTPs

| Technique | ID | Notes |
|-----------|----|-------|
| Phishing: Spearphishing Attachment | T1566.001 | Initial delivery via targeted spear-phishing emails |
| DLL Side-Loading | T1574.002 | SilkLurk loaded via legitimate signed binary |
| Process Injection | T1055 | SilkLurk injects into legitimate host processes |
| Create or Modify System Process: Windows Service | T1543.003 | SilkLurk installs as Windows service for persistence |
| Reflective Code Loading | T1620 | Memory-resident execution; no persistent disk payload |
| Input Capture: Keylogging | T1056.001 | OctLurk keylogger captures all keystrokes |
| Credentials from Password Stores: Credentials from Web Browsers | T1555.003 | OctLurk extracts browser-saved credentials |
| Email Collection | T1114 | OctLurk harvests mailbox contents |
| Obfuscated Files or Information | T1027 | Computer-name-based decryption prevents sandbox analysis |
| Command and Scripting Interpreter | T1059 | Remote command execution via OctLurk C2 |
| Ingress Tool Transfer | T1105 | Plugin modules loaded at runtime |

## Kill Chain

- **Delivery** — Spearphishing email targeting Central Asian government personnel
- **Exploitation** — User opens malicious attachment; initial dropper executes
- **Installation** — SilkLurk DLL side-loading establishes persistence via Windows service; OctLurk memory-resident payload injected
- **Command & Control** — Encrypted C2 via `dns.multitoconference[.]com` and `tj.tajikistandip[.]com`
- **Actions on Objectives** — Keylogging, credential theft, email collection, plugin-based capability expansion

## Remediation

| Action | Priority |
|--------|----------|
| Block C2 domains (`dns.multitoconference[.]com`, `tj.tajikistandip[.]com`) at DNS and proxy | High |
| Scan for MD5 `082d49ef9f14e6811d68c7e0e82e5069` across endpoints | High |
| Hunt for DLL side-loading via legitimate signed binaries in unusual directories | High |
| Inspect Windows services for recently created entries with suspicious binary paths | High |
| Review DNS and proxy logs for queries to `multitoconference[.]com` and `tajikistandip[.]com` | High |
| Enable memory scanning / in-memory detection rules in EDR | Medium |

## References

- [Kaspersky Securelist — OctLurk and SilkLurk: Stealthy Backdoors Targeting Central Asian Entities (2026-07-31)](https://securelist.com/octlurk-silklurk-backdoors-central-asia/120840/)
- [MITRE ATT&CK — T1574.002: DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/)
- [MITRE ATT&CK — T1055: Process Injection](https://attack.mitre.org/techniques/T1055/)
- [MITRE ATT&CK — T1620: Reflective Code Loading](https://attack.mitre.org/techniques/T1620/)
