---
scraped_at: 2026-11-22T00:00:00Z
source_url: https://unit42.paloaltonetworks.com/rrm-packages-pdf-reader-software/
report_type: threat-intel
severity: medium
title: "RRM Campaign: Phishing Distributes Fake PDF Reader MSI Delivering FleetDeck and ScreenConnect RMM Agents"
tags:
  - phishing
  - rmm-abuse
  - fleetdeck
  - screenconnect
  - t1219
  - t1204.002
  - t1566.002
  - cybercrime
---

# RRM Campaign: Phishing Distributes Fake PDF Reader MSI Delivering FleetDeck and ScreenConnect RMM Agents

**Published:** 2026-11-20
**Source:** Unit 42 (Palo Alto Networks)
**Severity:** Medium
**Analyst Note:** New campaign cluster uses fake PDF reader download lure to silently install FleetDeck or ScreenConnect remote management agents pre-configured to attacker-controlled tenants. No ransomware deployment observed yet; likely initial access and persistence for future monetization. Two distinct clusters identified.

---

## Executive Summary

Unit 42 documented an ongoing phishing campaign distributing malicious MSI installers disguised as a "PDF Reader" utility. When executed, the installer silently deploys either a **FleetDeck** (Cluster A) or **ScreenConnect** (Cluster B) remote management agent configured to connect to attacker-controlled management consoles. This provides persistent, low-noise remote access that blends with legitimate RMM traffic. The campaign overlaps in infrastructure with known cybercrime actors but lacks a definitive attribution link.

The technique mirrors the September 2026 Microsoft/Unit42 RMM phishing campaign (see `phishing_deployed_unauthorized_rmm_software.md`) but introduces FleetDeck — a newer RMM tool not covered by prior detections — and new delivery domains.

---

## Campaign Overview

**Campaign Name:** RRM (Remote Rogue Manager) — Unit 42 internal tracking name
**Active Since:** Approximately October 2026 (based on domain registration dates)
**Discovery Date:** 2026-11-20
**Delivery Method:** SEO-poisoned lure pages mimicking legitimate PDF reader download sites; possibly also distributed via spam email with download links
**Target Geography:** Primarily English-speaking users; targets appear opportunistic rather than sector-specific

### Kill Chain

1. **Delivery:** Victim directed to fake PDF reader download page (e.g., `files-reader-view[.]com`, `docprivates[.]shop`) via SEO poisoning or phishing link
2. **Exploitation (User Execution):** Victim downloads and runs `pdf_Reader_en_install.msi` (T1204.002)
3. **Installation:** MSI silently installs FleetDeck Agent or ScreenConnect client, configured to attacker-controlled management tenant; installer adds RMM agent as a Windows service (T1543.003)
4. **C2:** FleetDeck/ScreenConnect agent beacons to attacker management console over HTTPS; operator gains full remote control (T1219)

---

## IOCs

### Domains

| Domain | Cluster | Role | Date Added |
|--------|---------|------|------------|
| files-reader-view[.]com | A | Lure page — fake PDF reader download host | 2026-11-22 |
| darksupport[.]shop | A | C2/RMM tenant coordination infrastructure | 2026-11-22 |
| docprivates[.]shop | A | Lure domain | 2026-11-22 |
| fitarno[.]cloud | A | Lure domain | 2026-11-22 |
| creenlines[.]site | A | Lure domain | 2026-11-22 |
| scalvesonixands[.]site | A | Lure domain | 2026-11-22 |
| betweenhea[.]click | A | Lure domain | 2026-11-22 |
| cosscon[.]site | B | ScreenConnect look-alike management host | 2026-11-22 |
| codesphsere[.]ru | B | Lure domain (Cluster B) | 2026-11-22 |

### File Hashes

| Hash | Type | Description |
|------|------|-------------|
| `5393b2ec35dfe452392a60688b941796fddcb14c9b5df2a0db6b726f1bca074b` | SHA256 | `pdf_Reader_en_install.msi` — FleetDeck Agent installer; 24/70 VT detections |

---

## TTPs (MITRE ATT&CK)

| Technique ID | Technique Name | Notes |
|-------------|---------------|-------|
| T1566.002 | Phishing: Spearphishing Link | SEO-poisoned lure pages deliver download links |
| T1204.002 | User Execution: Malicious File | Victim executes fake PDF reader MSI |
| T1219 | Remote Access Software | FleetDeck or ScreenConnect installed as persistent RMM agent |
| T1543.003 | Create or Modify System Process: Windows Service | RMM agent installed as a Windows service for persistence |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 via HTTPS to attacker-controlled RMM management console |

---

## Malware & Tools

### FleetDeck Agent (Cluster A)
- Legitimate commercial RMM tool (fleetdeck.io)
- Installed silently via MSI; registers as Windows service
- Communicates via HTTPS to management console; no self-signed certs (uses FleetDeck cloud infrastructure, routes through attacker's tenant)
- Installer disguise: `pdf_Reader_en_install.msi` (SHA256: `5393b2ec35dfe452392a60688b941796fddcb14c9b5df2a0db6b726f1bca074b`)
- 24/70 VirusTotal detections (many AV engines lack FleetDeck signatures)

### ScreenConnect / ConnectWise (Cluster B)
- Installed with attacker-controlled instance URL (`cosscon[.]site`) baked into installer
- Same delivery mechanism as the September 2026 phishing campaign; new infrastructure domains

---

## Attribution

| Assessment | Confidence |
|-----------|-----------|
| Financially motivated cybercrime | High |
| English-speaking operator | Moderate |
| Nation-state involvement | Low (not assessed) |

No definitive attribution. Infrastructure overlaps with generic phishing-for-access campaigns. The introduction of FleetDeck (a newer, less-detected RMM tool) suggests actors are cycling through RMM tools as detection rates increase.

---

## Splunk Detection Searches

See: `detections/command_and_control/rrm_fleetdeck_pdf_masquerade_install.md`

Also see: `detections/command_and_control/phishing_deployed_unauthorized_rmm_software.md` (broader RMM phishing coverage including ScreenConnect/AnyDesk/MSP360)

```spl
`--- IOC-based domain hunt ---`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query IN ("files-reader-view.com","darksupport.shop","docprivates.shop",
    "fitarno.cloud","creenlines.site","scalvesonixands.site","betweenhea.click",
    "cosscon.site","codesphsere.ru")
by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src query answer
```

---

## References

- [Unit 42 — RRM Packages Disguised as PDF Reader Software (2026-11-20)](https://unit42.paloaltonetworks.com/rrm-packages-pdf-reader-software/)
- [Unit 42 Timely Threat Intel GitHub — raw IOC file](https://raw.githubusercontent.com/PaloAltoNetworks/Unit42-timely-threat-intel/main/2026-11-20-RRM-packages-disguised-as-PDF-reader-software.txt)
- [MITRE ATT&CK T1219 — Remote Access Software](https://attack.mitre.org/techniques/T1219/)
- [MITRE ATT&CK T1204.002 — User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [FleetDeck — Legitimate RMM vendor](https://fleetdeck.io/)
- Related: [Microsoft — Phishing Abuses RMM Tools (2026-09-29)](https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/)
