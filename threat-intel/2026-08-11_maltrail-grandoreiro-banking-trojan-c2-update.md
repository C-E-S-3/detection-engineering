---
scraped_at: 2026-08-11T00:00:00Z
source_url: https://github.com/stamparm/maltrail/commit/7d6600a
report_type: threat-intel
severity: medium
title: "Grandoreiro Banking Trojan C2 Infrastructure Update — LinkedIn Malspam Campaign (August 2026)"
---

# Grandoreiro Banking Trojan: C2 Infrastructure Update (August 2026)

**Source:** stamparm/maltrail commit 7d6600a (2026-08-11); LinkedIn malspam-grandoreiro post  
**Reference:** https://www.linkedin.com/posts/malspam-grandoreiro-ugcPost-7492945076373901312-chBn/  
**Severity:** Medium  

---

## Executive Summary

The maltrail threat intelligence trail for Grandoreiro was updated on 2026-08-11 with a batch of 15 new C2 IP addresses and 24 new domains (6 named domains + 18 Contabo VPS subdomains). The infrastructure is associated with an active LinkedIn malspam campaign delivering Grandoreiro that uses a "Dispositivo no compatible" (Device not compatible) browser fingerprinting lure to filter victims.

**Grandoreiro** is a well-documented Brazilian banking trojan (LATAM threat actor) that has been active since at least 2017. It primarily targets Spanish and Portuguese-speaking bank customers in Brazil, Spain, Mexico, and other Latin American countries. The trojan intercepts banking sessions via screen overlay injection and data exfiltration to C2 infrastructure. Despite Europol disruption operations in 2024, Grandoreiro continues to evolve and expand its C2 footprint.

---

## IOCs

### IP Addresses (New — August 2026)

All IPs communicate on port 443 (HTTPS).

| IP | Network Block | Notes |
|----|--------------|-------|
| 161.97.167.215 | 161.97.0.0/16 (Contabo GmbH) | Grandoreiro C2 |
| 161.97.184.143 | 161.97.0.0/16 (Contabo GmbH) | Grandoreiro C2 |
| 169.58.67.114 | 169.58.0.0/16 (IBM Cloud/SoftLayer) | Grandoreiro C2 |
| 169.58.67.117 | 169.58.0.0/16 (IBM Cloud/SoftLayer) | Grandoreiro C2 |
| 169.58.78.234 | 169.58.0.0/16 (IBM Cloud/SoftLayer) | Grandoreiro C2 |
| 169.58.84.218 | 169.58.0.0/16 (IBM Cloud/SoftLayer) | Grandoreiro C2 |
| 169.58.96.81 | 169.58.0.0/16 (IBM Cloud/SoftLayer) | Grandoreiro C2 |
| 169.58.96.181 | 169.58.0.0/16 (IBM Cloud/SoftLayer) | Grandoreiro C2 |
| 169.58.96.184 | 169.58.0.0/16 (IBM Cloud/SoftLayer) | Grandoreiro C2 |
| 169.58.97.33 | 169.58.0.0/16 (IBM Cloud/SoftLayer) | Grandoreiro C2 |
| 169.58.97.34 | 169.58.0.0/16 (IBM Cloud/SoftLayer) | Grandoreiro C2 |
| 169.58.97.43 | 169.58.0.0/16 (IBM Cloud/SoftLayer) | Grandoreiro C2 |
| 169.58.97.44 | 169.58.0.0/16 (IBM Cloud/SoftLayer) | Grandoreiro C2 |
| 178.238.234.36 | 178.238.0.0/16 (Contabo GmbH) | Grandoreiro C2 |
| 178.238.234.137 | 178.238.0.0/16 (Contabo GmbH) | Grandoreiro C2 |

### Domains (New — August 2026)

**Named lure/infrastructure domains:**

| Domain | Role |
|--------|------|
| divisascu.app | Financial services lure domain (Spanish: "divisas" = foreign exchange) |
| api.divisascu.app | API endpoint on financial lure domain |
| comohay.com | Lure domain (Spanish-language) |
| cosmeticvacations.com | Lure/redirect domain |
| devilmaycry.servehumour.com | Dynamic DNS C2 domain |
| security-auditialis.fr | Fake security domain (French TLD); likely victim filter/redirect |

**Contabo VPS C2 subdomains (new additions):**

| Domain |
|--------|
| vmi3236345.contaboserver.net |
| vmi3236347.contaboserver.net |
| vmi3236348.contaboserver.net |
| vmi3236352.contaboserver.net |
| vmi3236353.contaboserver.net |
| vmi3263303.contaboserver.net |
| vmi3263307.contaboserver.net |
| vmi3462145.contaboserver.net |
| vmi3462151.contaboserver.net |
| vmi3467394.contaboserver.net |
| vmi3469820.contaboserver.net |
| vmi3474446.contaboserver.net |
| vmi3474477.contaboserver.net |
| vmi3474478.contaboserver.net |
| vmi3474621.contaboserver.net |
| vmi3474622.contaboserver.net |
| vmi3474645.contaboserver.net |
| vmi3474647.contaboserver.net |

---

## Campaign Overview

### Delivery

The campaign is delivered via LinkedIn malspam. Victims receive a message or click a link leading to a page that displays a "Dispositivo no compatible" (Device not compatible) browser fingerprinting check — a known Grandoreiro technique to filter targets by locale, browser, and IP before serving the malicious payload. This technique helps the operators ensure payload delivery only reaches target demographics (Spanish/Portuguese-speaking users in banking-targeted regions) while avoiding sandbox analysis.

### Infrastructure Pattern

The C2 infrastructure shows Grandoreiro's established pattern of:
- **IBM Cloud/SoftLayer** (169.58.x.x): Primary C2 blocks; IBM Cloud accounts are frequently abused due to free trial availability
- **Contabo GmbH VPS** (161.97.x.x, 178.238.x.x, vmi*.contaboserver.net): Secondary C2 and fast-flux subdomains; Contabo's low-cost VPS infrastructure is a recurring Grandoreiro provider

The mix of numbered Contabo VM subdomains (vmi*.contaboserver.net) reflects Grandoreiro's fast-flux C2 rotation pattern, where new VPS instances are provisioned regularly to replace burned infrastructure.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Sub-technique | Description |
|--------|-----------|---------------|-------------|
| Initial Access | T1566 | T1566.003 | Spearphishing via Service — LinkedIn malspam delivery |
| Execution | T1204 | T1204.001 | User Execution: Malicious Link — victim opens lure URL |
| Defense Evasion | T1036 | | Masquerading — browser fingerprinting lure ("Dispositivo no compatible") |
| Defense Evasion | T1027 | | Obfuscated Files or Information — payload evasion techniques |
| Command and Control | T1071 | T1071.001 | Application Layer Protocol: Web Protocols — HTTPS on port 443 |
| Command and Control | T1568 | | Dynamic Resolution — vmi*.contaboserver.net fast-flux rotation |
| Credential Access | T1056 | T1056.001 | Input Capture: Keylogging — banking credential interception |
| Collection | T1113 | | Screen Capture — banking overlay injection |
| Exfiltration | T1041 | | Exfiltration Over C2 Channel — stolen credentials to C2 |

---

## Kill Chain

| Phase | Activity |
|-------|----------|
| **Delivery** | LinkedIn malspam delivers link to "Dispositivo no compatible" fingerprinting page |
| **Exploitation** | Victim passes fingerprint filter; banking trojan payload served |
| **Installation** | Grandoreiro installs persistence; hooks banking session intercept |
| **Command & Control** | HTTPS C2 to 169.58.x.x, 161.97.x.x, 178.238.x.x, and vmi*.contaboserver.net |
| **Actions on Objectives** | Banking credential theft via overlay injection; session hijacking; fraud |

---

## Associated Threat Actor

**Grandoreiro** — Brazilian LATAM banking trojan (active since ~2017)  
Operated by a loosely affiliated group of Brazilian cybercriminals. Europol conducted a disruptive arrest operation in January 2024, but the malware continues to circulate through other actors who obtained the source code or operate affiliated infrastructure.

**Geography:** Primary targets in Brazil, Spain, Mexico, Chile, Argentina; secondary targets in other Spanish/Portuguese-speaking markets.

---

## Detection & Hunting Opportunities

### Network-Based Detection

- Outbound HTTPS connections to any IP in the 169.58.67.x, 169.58.78.x, 169.58.84.x, 169.58.96.x, 169.58.97.x, 161.97.167.x, 178.238.234.x subnets from end-user workstations
- DNS queries resolving vmi*.contaboserver.net domains
- DNS queries for `divisascu.app`, `comohay.com`, `cosmeticvacations.com`, `devilmaycry.servehumour.com`, `security-auditialis.fr`

### Host-Based Detection

- Browser process making connections to IBM Cloud (169.58.x.x) infrastructure on port 443
- New processes or DLLs injected into browser processes following LinkedIn link clicks
- Unusual `chrome.exe` / `firefox.exe` child process spawning

---

## Remediation Recommendations

| Action | Priority |
|--------|----------|
| Block the 15 new C2 IPs at perimeter firewall and proxy | High |
| Add Grandoreiro domain IOCs to DNS blocklist | High |
| Enable LinkedIn access controls; consider restricting access on managed endpoints | Medium |
| Monitor for browser process injection (parent/child process anomalies) | Medium |
| Alert on outbound HTTPS to 169.58.0.0/16 from non-server endpoints (IBM Cloud abuse is common) | Medium |

---

## References

- [stamparm/maltrail Grandoreiro trail (commit 7d6600a, 2026-08-11)](https://github.com/stamparm/maltrail/commit/7d6600a)
- [LinkedIn malspam-grandoreiro reference post](https://www.linkedin.com/posts/malspam-grandoreiro-ugcPost-7492945076373901312-chBn/)
- [MITRE ATT&CK: T1566.003 — Spearphishing via Service](https://attack.mitre.org/techniques/T1566/003/)
- [MITRE ATT&CK: T1071.001 — Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [Europol Operation Grandoreiro (January 2024)](https://www.europol.europa.eu/media-press/newsroom/news/grandoreiro-banking-trojan-suspects-arrested)
