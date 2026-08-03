---
scraped_at: 2026-08-03T06:00:00Z
source_url: https://www.group-ib.com/blog/hollowframe-matryoshka-law-firm-campaign/
report_type: threat-intel
severity: high
title: "HollowFrame & Matryoshka: Go Loader + Rust Backdoor Targeting Law Firms via Spear-Phishing LNK"
---

# HollowFrame & Matryoshka — Law Firm Espionage Campaign

**Source:** Group-IB  
**Published:** 2026-07-31  
**Severity:** High  

## Summary

Group-IB published research on 2026-07-31 describing a novel two-stage malware family targeting law firms via spear-phishing. The campaign uses a **Go-based loader** named **HollowFrame** to deploy a **Rust-based backdoor** named **Matryoshka**. The threat actor is currently unattributed.

The campaign is notable for its use of **private GitHub repositories as C2 infrastructure** — an increasingly common technique that abuses trusted hosting services to blend C2 traffic with legitimate developer activity and evade network-layer detection.

## Technical Details

### Attack Chain

1. **Delivery** — Targeted spear-phishing email to law firm personnel (attorneys, paralegals, legal staff)
2. **Execution** — Malicious LNK shortcut file; when opened, executes HollowFrame loader
3. **Installation** — HollowFrame performs DLL side-loading via a legitimate Python interpreter binary to bypass application allowlisting
4. **Privilege Escalation** — HollowFrame performs privilege escalation prior to deploying Matryoshka
5. **Backdoor deployment** — Matryoshka Rust backdoor installed as the persistent payload

### HollowFrame (Go Loader)

- Written in Go; cross-platform compilation capability
- DLL side-loading via legitimate, signed Python binary (abuses Python interpreter DLL search order)
- Anti-analysis checks before payload deployment:
  - System uptime check (sandbox evasion — sandboxes often have short uptimes)
  - Memory size check (sandbox evasion)
  - File count check (sandbox evasion — sandboxes have few files)
  - Cursor movement check (sandbox evasion — sandboxes lack genuine user interaction)
- Performs privilege escalation prior to Matryoshka deployment

### Matryoshka (Rust Backdoor)

- Written in Rust — benefits from Rust's memory safety, lack of common C/C++ artifacts, and relative rarity in malware families
- Two C2 variants:
  - **HTTP variant** — standard HTTP-based C2 communication
  - **GitHub variant** — uses private GitHub repositories as C2 channel; commands issued via repository commits/issues/files; results exfiltrated similarly
- Backdoor capabilities (inferred from C2 structure): remote command execution, file upload/download, persistence

## Targeting

- **Sector:** Legal (law firms, attorneys, legal service providers)
- **Geography:** Not yet confirmed; campaign appears global in targeting scope
- **Attribution:** Unattributed as of 2026-07-31

## IOCs

No specific public IOC hashes, domains, or IP addresses have been released as of the Group-IB publication date. Group-IB indicates indicators are being shared via private threat intelligence channels.

Analysts should hunt behaviorally using the TTP indicators below.

## MITRE ATT&CK TTPs

| Technique | ID | Notes |
|-----------|----|-------|
| Phishing: Spearphishing Attachment | T1566.001 | LNK file delivered via spear-phishing email |
| Malicious Link | T1204.001 | LNK shortcut as delivery mechanism |
| DLL Side-Loading | T1574.002 | HollowFrame DLL side-loading via legitimate Python binary |
| Virtualization/Sandbox Evasion | T1497 | Uptime, memory, file count, cursor movement checks |
| Abuse Elevation Control Mechanism | T1548 | Privilege escalation prior to Matryoshka deployment |
| Web Service: Dead Drop Resolver | T1102.001 | Private GitHub repo used as C2 channel |
| Command and Scripting Interpreter | T1059 | Remote command execution via Matryoshka backdoor |
| Ingress Tool Transfer | T1105 | File upload/download capability |

## Kill Chain

- **Delivery** — Spear-phishing email with malicious LNK attachment
- **Exploitation** — LNK execution triggers HollowFrame Go loader
- **Installation** — DLL side-loading via Python binary; privilege escalation; Matryoshka Rust backdoor deployed
- **Command & Control** — HTTP or private GitHub repository C2 channel
- **Actions on Objectives** — Remote command execution, data collection from legal sector targets

## Hunting Notes

Due to no public IOCs, analysts should hunt for behavioral indicators:

- LNK files spawning Python interpreter processes from unusual directories
- Python interpreter (`python.exe`, `pythonw.exe`) loading unsigned DLLs from writable paths (AppData, Temp, ProgramData)
- Outbound connections from Python interpreter processes (unusual — Python should not be calling home in most environments)
- Network connections to `api.github.com` or `raw.githubusercontent.com` from non-developer workstations (especially legal/professional services environments)
- Short-lived processes performing uptime and memory enumeration checks

## References

- [Group-IB — HollowFrame & Matryoshka: Novel Malware Targeting Law Firms (2026-07-31)](https://www.group-ib.com/blog/hollowframe-matryoshka-law-firm-campaign/)
- [MITRE ATT&CK — T1574.002: DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/)
- [MITRE ATT&CK — T1102.001: Web Service: Dead Drop Resolver](https://attack.mitre.org/techniques/T1102/001/)
- [MITRE ATT&CK — T1497: Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1497/)
