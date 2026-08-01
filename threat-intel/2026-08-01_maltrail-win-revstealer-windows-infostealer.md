---
scraped_at: "2026-08-01T00:00:00Z"
source_url: https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/revstealer.txt
report_type: threat-intel
severity: high
title: "RevStealer — New Windows Infostealer, 260 C2 Domains, First Seen July 31 2026"
---

# RevStealer — New Windows Infostealer, 260 C2 Domains

A new Windows information-stealing malware family named RevStealer was identified by ThreatFox/abuse.ch on July 31, 2026. Maltrail (stamparm/maltrail) added a dedicated trail file on July 31 referencing the ThreatFox Win.RevStealer tag. The malware uses 260 domain-based C2 endpoints — a large infrastructure footprint for a newly identified family. Attribution is currently unknown.

## 1. IOCs

### C2 Domains (Representative Sample — 25 of 260)

| Domain | Subdomain Pattern | Notes |
|--------|-------------------|-------|
| `alpha-zone.click` | — | RevStealer C2 |
| `amberscreen.lol` | — | RevStealer C2 |
| `apiforge.click` | — | RevStealer C2 |
| `aqua-grid77.xyz` | — | RevStealer C2 |
| `atlasbyte.xyz` | `api.atlasbyte.xyz` | RevStealer C2 + API subdomain |
| `autoscope.sbs` | `api.autoscope.sbs` | RevStealer C2 + API subdomain |
| `bench-grid.one` | — | RevStealer C2 |
| `birch-studio29.one` | — | RevStealer C2 |
| `brewtrail.click` | — | RevStealer C2 |
| `brighttempo.lol` | — | RevStealer C2 |
| `calmtexture.click` | — | RevStealer C2 |
| `cchain-gov.org` | `eth.cchain-gov.org` | RevStealer C2; crypto/ETH naming |
| `cchain.pro` | `eth.cchain.pro` | RevStealer C2; crypto/ETH naming |
| `cchaingov.org` | `eth.cchaingov.org` | RevStealer C2; crypto/ETH naming |
| `ccw.lat` | `eth.ccw.lat` | RevStealer C2; crypto/ETH naming |
| `cdnbazaar.xyz` | — | RevStealer C2 |
| `civicblaze.click` | — | RevStealer C2 |
| `craftlayer.click` | — | RevStealer C2 |
| `deepclimate.click` | — | RevStealer C2 |
| `easttrail5.xyz` | — | RevStealer C2 |
| `everatlas.lol` | `proxy.everatlas.lol` | RevStealer C2 + proxy subdomain |
| `fastmoneyflux.com` | — | RevStealer C2 |
| `hexatecha.com` | — | RevStealer C2 |
| `nexbu.cloud` | `sancamilowebhook.nexbu.cloud` | RevStealer C2 + webhook relay |
| `youthchain.cc` | `eth.youthchain.cc` | RevStealer C2; crypto/ETH naming |

Full IOC list (260 domains): https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/revstealer.txt

### Infrastructure Patterns

Ethereum/crypto-themed domain patterns (`cchain*`, `eth.*`, `youthchain*`) suggest possible cryptocurrency theft focus or branding to evade domain reputation filtering. API and proxy subdomains (`api.*`, `proxy.*`) are consistent with exfiltration endpoints.

TLDs used: `.click`, `.lol`, `.xyz`, `.sbs`, `.one`, `.org`, `.pro`, `.lat`, `.cloud`, `.monster`, `.pics`, `.net`, `.id`, `.az`, `.com`, `.cc` — diverse registrar spread to complicate bulk blocking.

## 2. TTPs

| Tactic | Technique ID | Technique |
|--------|-------------|-----------|
| Collection | T1005 | Data from Local System (credential/session theft) |
| Collection | T1552.001 | Unsecured Credentials: Credentials In Files |
| Exfiltration | T1041 | Exfiltration Over C2 Channel |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols |
| Command and Control | T1568 | Dynamic Resolution (diverse TLD/domain fleet) |

## 3. Threat Context

| Attribute | Value |
|-----------|-------|
| Malware family | RevStealer |
| Platform | Windows |
| Category | Information Stealer |
| First observed | 2026-07-31 |
| Attribution | Unknown |
| IOC count | 260 domains |
| Source | ThreatFox (abuse.ch), Maltrail |
| MaaS model | Likely (large infra suggests multi-operator) |

No behavioral IOCs (hashes, process names, registry keys, mutexes) are publicly available as of 2026-08-01. Domain-based detection is the primary defensive option.

## 4. Lockheed Martin Kill Chain

**Command & Control** — C2 infrastructure phase (domain fleet used to receive stolen data and send tasking).

## 5. Splunk Detection

See `detections/command_and_control/revstealer_dns_c2_lookup.md` for a Network_Resolution.DNS-based detection that alerts on DNS queries to known RevStealer domains.

## 6. References

- [Maltrail RevStealer trail file](https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/revstealer.txt)
- [ThreatFox Win.RevStealer](https://threatfox.abuse.ch/browse/malware/win.revstealer/)
- [Maltrail GitHub — stamparm/maltrail](https://github.com/stamparm/maltrail)
