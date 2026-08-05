---
scraped_at: 2026-08-05T06:00:00Z
source_url: https://www.ransomware.live/group/Orova
report_type: threat-intel
severity: high
title: "Orova Ransomware — New Group Emerges; 14 Victims Across US, Hong Kong, Taiwan (July–August 2026)"
---

# Orova Ransomware — New Threat Group with Active Leak Site; US, HK, Taiwan Focus

**Source:** ransomware.live / ransomwhere.org  
**Published:** 2026-08-04 (14-victim tracking as of this date)  
**Severity:** High  
**First Seen:** 2026-07-07

## Summary

Orova is a newly identified ransomware threat group first observed on 2026-07-07. As of 2026-08-04, Orova has posted 14 victims to its dedicated leak site (DLS) hosted on Tor. Victims are concentrated in the United States (7), Hong Kong (4), and Taiwan (3), spanning retail, healthcare, manufacturing, agriculture, and financial services sectors. The group operates a two-Tor-onion infrastructure: a public data-leak site for victim naming/shaming and a private chat portal for ransom negotiation.

No technical analysis or malware samples are publicly available as of this report. Orova's TTP profile is inferred from its victim sector and geography, consistent with opportunistic double-extortion ransomware operators rather than a nation-state-sponsored group.

## Victim Profile

| Country | Count |
|---------|-------|
| United States | 7 |
| Hong Kong | 4 |
| Taiwan | 3 |

**Sectors affected:** Retail, healthcare, manufacturing, agriculture, financial services

**Named victims (as posted to Orova DLS as of 2026-08-04):**

| Organization | Country / Sector |
|---|---|
| Ultra Fame | — |
| Cardiology Associates | US / Healthcare |
| Yost Home Improvements | US / Retail/Construction |
| KINGSSON | — |
| SSI Holding (Far East) | HK |
| Sanrio Hong Kong | HK / Retail |
| Tat Fung Textile | HK / Manufacturing |
| Integrated Site Management | — |
| Conceptual Designs Inc. | — |
| JK Capital Management | — / Financial Services |
| Global Friction Products | — / Manufacturing |

## IOCs

### Tor Infrastructure

| Indicator | Type | Context |
|-----------|------|---------|
| `mll5ddmdzgiq2siv3qnocmmqyiigfpajtc663xtf32qtp6weycyx2hyd.onion` | Tor .onion | Orova ransomware Data Leak Site (DLS) — victim naming/shaming |
| `ns7y6bxawualjj5rpo5num6syejd7hgaowrndk3r4duxu2iyinzv6hid.onion` | Tor .onion | Orova ransomware chat/negotiation portal |

*Source for Tor addresses: stamparm/maltrail (2026-08-04), citing [@fbgwls245 on X](https://x.com/fbgwls245/status/2084638533348913417)*

## MITRE ATT&CK TTPs

> TTPs below are inferred from the group's victim profile and double-extortion model. No technical malware analysis is available.

| Technique | ID | Notes |
|-----------|----|-------|
| Data Encrypted for Impact | T1486 | Ransomware encryption of victim files |
| Exfiltration Over Web Service | T1567 | Data exfiltrated prior to encryption for double-extortion leak site |
| Financial Theft | T1657 | Ransom demand for decryption key and non-publication of stolen data |

## Kill Chain

- **Actions on Objectives** — Data exfiltration + file encryption; ransom demands published to Tor leak site

## Threat Actor Profile

| Attribute | Value |
|-----------|-------|
| Name | Orova |
| Type | Ransomware group (double-extortion) |
| First seen | 2026-07-07 |
| Primary targets | US, Hong Kong, Taiwan; retail, healthcare, manufacturing, financial |
| Infrastructure | Two Tor hidden services (DLS + negotiation portal) |
| Attribution | Unknown; likely financially motivated |
| Nation-state nexus | None assessed |

## Remediation and Hunting

| Action | Priority |
|--------|----------|
| Add Orova .onion domains to outbound threat intel watchlists | High |
| If Tor exit-node traffic is monitored, alert on Tor connections from corporate assets | Medium |
| Review backup integrity and ransomware-readiness posture for organizations in targeted sectors | High |
| Watch for updates as malware samples become available for behavioral IOC extraction | Medium |

## References

- [ransomware.live — Orova Group](https://www.ransomware.live/group/Orova)
- [ransomwhere.org — Orova](https://ransomwhere.org/groups/Orova)
- [stamparm/maltrail — orova_ransomware.txt](https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/orova_ransomware.txt)
- [MITRE ATT&CK — T1486: Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
