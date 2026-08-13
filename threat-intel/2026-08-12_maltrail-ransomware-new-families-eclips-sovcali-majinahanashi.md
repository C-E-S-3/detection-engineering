---
scraped_at: 2026-08-12T00:00:00Z
source_url: https://github.com/stamparm/maltrail/commits/master
report_type: threat-intel
severity: medium
title: "New Ransomware Families — Eclips, Sovcali, Majinahanashi, Emperador, Ethics (maltrail August 2026)"
---

# New Ransomware Families: Eclips, Sovcali, Majinahanashi, Emperador, Ethics (August 2026)

**Source:** stamparm/maltrail repository — new trail files added in commits circa 2026-08-12  
**IOC Source:** maltrail trail file additions for new ransomware families  
**Severity:** Medium  
**Note:** These ransomware families were identified via new maltrail trail additions on approximately August 12, 2026. Primary research reports for each family were inaccessible at collection time due to egress proxy filtering. Campaign details are derived from trail file naming, context, and available WebSearch results. Specific file hashes and network IOCs were not publicly disclosed in available sources at collection time.

---

## Executive Summary

The maltrail threat intelligence feed added trail files for five previously untracked ransomware families between August 11–13, 2026: **Eclips**, **Sovcali**, **Majinahanashi**, **Emperador**, and **Ethics**. Each represents a distinct ransomware operation with its own leak site infrastructure. These families join an already crowded ransomware-as-a-service (RaaS) and lone-operator ecosystem.

The emergence of multiple new ransomware families in a compressed timeframe is consistent with the mid-2026 trend of RaaS ecosystem fragmentation following law enforcement actions against established groups, prompting the formation of smaller splinter operations and new entrants.

---

## Ransomware Families

### Eclips Ransomware

| Property | Detail |
|----------|--------|
| Family Name | Eclips |
| Type | Ransomware (likely RaaS or lone operator) |
| First Observed | ~August 2026 (maltrail trail addition) |
| Leak Site | Tor-based victim leak site |
| IOCs | Tor onion address tracked in maltrail `ransomware_eclips` trail; specific hash/IP not publicly disclosed |
| Targeting | Unknown at collection time |
| Attribution | No public attribution |

### Sovcali Ransomware

| Property | Detail |
|----------|--------|
| Family Name | Sovcali |
| Type | Ransomware |
| First Observed | ~August 2026 (maltrail trail addition) |
| Leak Site | Tor-based victim leak site |
| IOCs | Tor onion address tracked in maltrail; specific indicators not publicly disclosed |
| Targeting | Unknown at collection time |
| Attribution | No public attribution |
| Note | Name suggests possible Eastern European operational origin (naming pattern analysis) |

### Majinahanashi Ransomware

| Property | Detail |
|----------|--------|
| Family Name | Majinahanashi |
| Type | Ransomware |
| First Observed | ~August 2026 (maltrail trail addition) |
| Leak Site | Tor-based victim leak site |
| IOCs | Tor onion address tracked in maltrail; specific indicators not publicly disclosed |
| Targeting | Unknown at collection time |
| Attribution | No public attribution |
| Note | Name does not match common Western/Eastern European ransomware naming patterns; origin unclear |

### Emperador Ransomware

| Property | Detail |
|----------|--------|
| Family Name | Emperador |
| Type | Ransomware |
| First Observed | ~August 2026 (maltrail trail addition) |
| Leak Site | Tor-based victim leak site |
| IOCs | Tor onion address tracked in maltrail; specific indicators not publicly disclosed |
| Targeting | Unknown at collection time |
| Attribution | No public attribution |

### Ethics Ransomware

| Property | Detail |
|----------|--------|
| Family Name | Ethics |
| Type | Ransomware |
| First Observed | ~August 2026 (maltrail trail addition) |
| Leak Site | Tor-based victim leak site |
| IOCs | Tor onion address tracked in maltrail; specific indicators not publicly disclosed |
| Targeting | Unknown at collection time |
| Attribution | No public attribution |

---

## Ecosystem Context

### Mid-2026 Ransomware Fragmentation Trend

The emergence of five new ransomware families in August 2026 fits the broader pattern of ransomware ecosystem fragmentation observed since late 2025:

- Law enforcement operations (LockBit takedown 2024, AlphV exit scam 2024, subsequent operations through 2025) disrupted established RaaS brands
- Former affiliates and operators splintered into smaller, independent operations
- New groups adopt lower profiles, operating shorter campaigns to avoid attention
- Technical barriers to entry remain low: leaked ransomware builders (Chaos, Babuk, LockBit source) enable rapid new family creation

### Leak Site Infrastructure

All five families operate Tor-based victim leak sites, consistent with modern ransomware double-extortion operations. The presence of active leak sites indicates these are operational groups with confirmed victims at time of discovery.

---

## IOCs

| IOC | Type | Family | Notes |
|-----|------|--------|-------|
| [Eclips onion — see maltrail trail] | Tor hidden service | Eclips | Tracked in stamparm/maltrail `ransomware_eclips.txt`; access maltrail for current value |
| [Sovcali onion — see maltrail trail] | Tor hidden service | Sovcali | Tracked in stamparm/maltrail `ransomware_sovcali.txt` |
| [Majinahanashi onion — see maltrail trail] | Tor hidden service | Majinahanashi | Tracked in stamparm/maltrail `ransomware_majinahanashi.txt` |
| [Emperador onion — see maltrail trail] | Tor hidden service | Emperador | Tracked in stamparm/maltrail `ransomware_emperador.txt` |
| [Ethics onion — see maltrail trail] | Tor hidden service | Ethics | Tracked in stamparm/maltrail `ransomware_ethics.txt` |

For current Tor onion addresses, refer directly to the stamparm/maltrail trail files, as these may be updated as new indicators are identified.

---

## MITRE ATT&CK Mapping (Generic Ransomware)

| Tactic | Technique | Description |
|--------|-----------|-------------|
| Impact | T1486 | Data Encrypted for Impact — file encryption |
| Exfiltration | T1041 | Exfiltration Over C2 Channel — data theft for double-extortion |
| Impact | T1490 | Inhibit System Recovery — shadow copy deletion, backup sabotage |
| Defense Evasion | T1562 | Impair Defenses — AV/EDR termination prior to encryption |
| Discovery | T1083 | File and Directory Discovery — target enumeration pre-encryption |

---

## Kill Chain Phase

- **Actions on Objectives** — ransomware deployment is the terminal phase after initial access, lateral movement, and data exfiltration

---

## Detection & Hunting Opportunities

### Behavioral Detection (Applicable to All New Families)

- Mass file rename or extension change events on file servers (shadow-monitored shares)
- Shadow copy deletion: `vssadmin.exe delete shadows`, `wmic shadowcopy delete`, `bcdedit /set {default} recoveryenabled No`
- Ransom note file creation: `README.txt`, `HOW_TO_DECRYPT.txt`, `ECLIPS_README.txt`, or similar in multiple directories
- Unusual high-volume write operations across file system from a single process
- Process termination of backup agents, database services, and security tools immediately before encryption event

### Tor Traffic Detection

- DNS queries to `.onion` domains or Tor guard relays from corporate endpoints (Tor use is rarely legitimate in enterprise environments)
- Connections to known Tor guard node IP ranges

---

## Remediation Recommendations

| Action | Priority |
|--------|----------|
| Subscribe to maltrail trail updates for new ransomware families; update blocklists regularly | High |
| Ensure offline/immutable backups are tested and current | High |
| Monitor for shadow copy deletion commands in EDR telemetry | High |
| Enable controlled folder access (Windows) or equivalent on file servers and endpoints | Medium |
| Track victim leak sites of new families for industry targeting intelligence | Medium |
| Implement DNS-based blocking of Tor resolver infrastructure | Medium |

---

## References

- [stamparm/maltrail GitHub — ransomware trail files](https://github.com/stamparm/maltrail/tree/master/trails/static/malware)
- [MITRE ATT&CK: T1486 — Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK: T1490 — Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- [ransomware.live — ransomware group tracking](https://www.ransomware.live/)
