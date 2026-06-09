---
scraped_at: 2026-06-09T00:00:00Z
source_url: https://thehackernews.com/2026/06/android-spyware-asin-targets-arabic.html
report_type: threat-intel
severity: medium
title: "Asin Android Spyware Targets Arabic-Speaking Users via Fake News, PDF Reader, and War Map Applications"
---

## 1. IOCs

### Domains
| Indicator | Role |
|-----------|------|
| c-pdf[.]net | APK download domain (December 2025 sample downloaded by Xiaomi device running Android 15) |
| syriadefensemap[.]com | Fake "Syria Defense Map" app delivery domain (January 2026 sample, Xiaomi Redmi Note 13 Pro+ 5G running Android 15) |
| govlens[.]net | Additional Asin distribution domain identified by ESET |

### File Artifacts
| Artifact | Detail |
|----------|--------|
| VirusTotal sample | Uploaded from Türkiye, October 2025; earliest known Asin sample |
| APK source | c-pdf[.]net (PDF reader lure, December 2025) |
| APK source | syriadefensemap[.]com (Syria Defense Map lure, January 2026) |

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1476 | Deliver Malicious App via Authorized App Store | Asin is distributed as sideloaded APKs from attacker-controlled domains (not Play Store); users are directed to download and manually install the app |
| Defense Evasion | T1444 | Masquerade as Legitimate Application | APKs disguise themselves as PDF readers, government news portals, and war map utilities relevant to Arabic-speaking users |
| Collection | T1422 | System Network Configuration Discovery | Asin collects device configuration and network information |
| Collection | T1430 | Location Tracking | Spyware tracks device GPS location |
| Collection | T1533 | Data from Local System | Harvests SMS messages, call logs, contacts, device identifiers |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | Exfiltrates harvested data to operator-controlled C2 infrastructure |

## 3. Malware & Tools

| Name | Type | Description |
|------|------|-------------|
| Asin | Android Spyware | Previously undocumented Android spyware discovered by ESET; distributed through distinct campaign waves using different lure themes (utility apps, war-related updates, government news sources); targets Arabic-speaking users; requires manual installation and permission grant; first sample detected October 2025 (VirusTotal, Türkiye origin); campaign waves active through at least January 2026 |

## 4. Threat Actor / Campaign Attribution

| Attribute | Detail |
|-----------|--------|
| Actor | Unknown / unattributed (ESET notes cluster remains unattributed) |
| Motivation | Espionage / intelligence collection based on targeting profile |
| First seen | October 2025 (VirusTotal upload from Türkiye) |
| Active period | October 2025 – at least January 2026; multiple distinct campaign waves |
| Geographic targeting | Arabic-speaking users, primarily Middle East and North Africa; Turkish IP submitted earliest sample |
| Likely targets | Journalists, OSINT researchers, and activists in Arabic-speaking regions based on lure selection (Syria Defense Map, government news) |
| Distribution method | Sideloaded APKs from attacker-controlled domains; social engineering to convince users to grant permissions |

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_host IN ("c-pdf.net","syriadefensemap.com","govlens.net")
  by All_Traffic.src All_Traffic.dest_host All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=80
| table firstTime lastTime src dest_host dest_port risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query IN ("c-pdf.net","syriadefensemap.com","govlens.net")
  by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=80
| table firstTime lastTime src query answer risk_score
```

## 6. Executive Summary

ESET researchers disclosed a previously undocumented Android spyware family named **Asin** that has been targeting Arabic-speaking users since at least October 2025 through multiple distinct campaign waves. Each wave deploys distinct distribution infrastructure and uses different social engineering lures relevant to the target audience: PDF reader utilities, government news portals, and war-related map applications.

Asin is distributed as sideloaded APKs from attacker-controlled domains rather than through official app stores. Once installed with user-granted permissions, it functions as a full-featured mobile spyware collecting SMS messages, call logs, contacts, device identifiers, GPS location, and related data.

ESET has not attributed the activity cluster to any known threat actor. Based on the lure selection — particularly the "Syria Defense Map" application theme and targeting of government-related content — the primary targets are assessed to be journalists, OSINT researchers, and political activists in Arabic-speaking regions. The earliest confirmed sample was uploaded to VirusTotal from Türkiye in October 2025, with subsequent campaign waves continuing through at least January 2026.
