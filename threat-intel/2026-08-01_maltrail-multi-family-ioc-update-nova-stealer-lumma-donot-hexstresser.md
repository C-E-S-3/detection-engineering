---
scraped_at: "2026-08-01T00:00:00Z"
source_url: https://github.com/stamparm/maltrail
report_type: threat-intel
severity: medium
title: "Maltrail Multi-Family IOC Update — Nova Stealer (69 new domains), LummaC2, DoNot APT, Mirai/HexStresser (July 30-31 2026)"
---

# Maltrail Multi-Family IOC Update — July 30-31 2026

Maltrail (stamparm/maltrail) commits on July 30-31, 2026 added new C2 infrastructure for four threat families: Nova Stealer macOS infostealer (69 new domains in an "aether/argent/borea" naming wave), LummaC2 (1 new domain), DoNot APT (APT-C-35, 1 new domain), and Mirai/HexStresser DDoS botnet (1 new IP and 1 new domain).

## 1. Nova Stealer (osx_nova) — macOS Infostealer

**Aliases:** CrashStealer, miolab stealer, pamstealer  
**Platform:** macOS  
**Sources:** @solostalking, @suyog41, VirusTotal  

### New C2 Domains (69 added July 30 2026, aether/argent/borea naming wave — 20 representative)

| Domain | TLD | Notes |
|--------|-----|-------|
| `aethercloudkeep.shop` | .shop | Nova Stealer C2; aether wave |
| `aetherflintrun.pro` | .pro | Nova Stealer C2; aether wave |
| `aetherhollowcrest.pro` | .pro | Nova Stealer C2; aether wave |
| `argentmistbridge.pro` | .pro | Nova Stealer C2; argent wave |
| `argentsnowpath.pro` | .pro | Nova Stealer C2; argent wave |
| `astralfluxpeak.pro` | .pro | Nova Stealer C2 |
| `boreafluxvale.pro` | .pro | Nova Stealer C2; borea wave |
| `crimsonmistglen.shop` | .shop | Nova Stealer C2 |
| `garnetdawntrail.pro` | .pro | Nova Stealer C2 |
| `jasperwindwell.pro` | .pro | Nova Stealer C2 |
| `karmicashenstead.shop` | .shop | Nova Stealer C2 |
| `lumenfluxnexus.shop` | .shop | Nova Stealer C2 |
| `meridiancloudmarch.shop` | .shop | Nova Stealer C2 |
| `nimbusrivershore.pro` | .pro | Nova Stealer C2 |
| `onyxdawnfrontier.pro` | .pro | Nova Stealer C2 |
| `ravenrainspire.pro` | .pro | Nova Stealer C2 |
| `solsticecindergrove.pro` | .pro | Nova Stealer C2 |
| `tempestcinderfall.pro` | .pro | Nova Stealer C2 |
| `velvetbrightwell.pro` | .pro | Nova Stealer C2 |
| `willowbirchcore.pro` | .pro | Nova Stealer C2 |

**Existing known IPs:** 196.251.107.220, 196.251.107.221, 196.251.107.97 (previously tracked)

Full list: https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/osx_nova.txt

---

## 2. LummaC2 (Lumma Stealer) — New Domain

**Platform:** Windows MaaS  
**New IOC:** `globalprotextetx.cc`  
**Source:** https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/lummac2.txt  

| Domain | Notes |
|--------|-------|
| `globalprotextetx.cc` | LummaC2 C2 domain; impersonates GlobalProtect VPN branding |

---

## 3. DoNot APT (APT-C-35 / StealJob) — New Domain

**Attribution:** India-nexus APT; targets Pakistan, Kashmir, South Asian governments/military  
**New IOC:** `juffysolute.info`  
**Source:** https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/donot.txt  

| Domain | Notes |
|--------|-------|
| `juffysolute.info` | DoNot APT C2 domain; added July 31 2026 |

**Previously tracked DoNot domains (do not re-add):** logshopperz.info, quickly21.com, virgology.info

---

## 4. Mirai/HexStresser — New IP and Domain

**Family:** Mirai-variant ELF botnet operated as DDoS-for-hire (HexStresser)  
**New IOCs:**

| Indicator | Type | Notes |
|-----------|------|-------|
| `31.77.227.104` | IP | HexStresser C2 infrastructure; added July 31 2026 |
| `pick.hexstresser.org` | Domain | HexStresser C2 / panel domain; added July 31 2026 |

---

## 5. MITRE ATT&CK Mapping

| Threat | Tactic | Technique ID | Technique |
|--------|--------|-------------|-----------|
| Nova Stealer | Collection | T1005 | Data from Local System (macOS) |
| Nova Stealer | Exfiltration | T1041 | Exfiltration Over C2 Channel |
| LummaC2 | Collection | T1552.001 | Credentials In Files |
| LummaC2 | Command and Control | T1071.001 | Web Protocols |
| DoNot APT | Command and Control | T1071.001 | Web Protocols |
| DoNot APT | Persistence | T1053.005 | Scheduled Task |
| HexStresser | Command and Control | T1095 | Non-Application Layer Protocol |
| HexStresser | Impact | T1498 | Network Denial of Service |

## 6. References

- [Maltrail osx_nova trail](https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/osx_nova.txt)
- [Maltrail LummaC2 trail](https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/lummac2.txt)
- [Maltrail DoNot trail](https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/donot.txt)
- [MITRE ATT&CK — DoNot Team (G0055)](https://attack.mitre.org/groups/G0055/)
- [Maltrail GitHub commits July 30-31 2026](https://github.com/stamparm/maltrail/commits/master/trails/static/malware)
