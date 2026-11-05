---
scraped_at: 2026-11-05T00:00:00Z
source_url: https://www.sekoia.com/blog/poisoned-source-apt29-watering-holes-targets-mobile-devices-with-n-day-exploits
report_type: threat-intel
severity: high
title: "APT29 Poisoned Source: Plerdy Analytics Supply Chain Watering Hole Delivers DarkSword (iOS) and AndroSnitch (Android)"
---

# APT29 Poisoned Source: Plerdy Analytics Supply Chain Watering Hole Delivers DarkSword (iOS) and AndroSnitch (Android)

**Source:** Sekoia Threat Intelligence  
**Published:** 2026-11-04  
**Severity:** High  
**Attribution confidence:** Moderate-to-high (APT29 / SVR / Cozy Bear)

---

## 1. IOCs

### Domains (watering-hole / delivery infrastructure)

| Indicator | Role | Context |
|-----------|------|---------|
| `theowo[.]club` | Watering-hole delivery domain | JavaScript fingerprinting gate; serves platform-specific exploit chain |
| `america250[.]holiday` | Watering-hole delivery domain | Lookalike patriotic-themed domain routing mobile visitors to exploit chain |
| `static.flux-telemetry[.]com` | Staging / delivery domain | Mimics analytics telemetry; used to stage exploit payloads in Plerdy supply chain campaign |
| `adsprism-stat[.]com` | Fake analytics / redirect domain | Impersonates ad-statistics service; watering-hole redirect node |

### Hashes

| Indicator | Type | Malware | Context |
|-----------|------|---------|---------|
| `387a7fb768db1350a9788d9704e7a72abe07152734e0ff026af72b417e36268c` | SHA256 | AndroSnitch | Android payload dropped via CVE-2026-3910 + CVE-2025-27038; steals Chrome cookie databases and Wi-Fi passwords |

### CVEs Exploited

| CVE | Platform | CVSS | Description |
|-----|----------|------|-------------|
| CVE-2025-43529 | iOS 18.5 | — | iOS kernel privilege escalation; part of DarkSword iOS chain |
| CVE-2026-20700 | iOS 18.5 | — | iOS WebKit memory corruption; initial remote exploit in DarkSword chain |
| CVE-2025-14174 | iOS 18.5 | — | iOS sandbox escape; DarkSword chain |
| CVE-2025-43510 | iOS 18.5 | — | iOS IPC privilege escalation; DarkSword chain |
| CVE-2025-43520 | iOS 18.5 | — | iOS kernel code execution; final DarkSword chain stage |
| CVE-2026-3910 | Android (Chrome 139-145 excl. 143) | — | Chrome renderer memory corruption; AndroSnitch delivery |
| CVE-2025-27038 | Android (Chrome 139-145 excl. 143) | — | Chrome sandbox escape; AndroSnitch delivery |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique | ID | Notes |
|--------|-----------|-----|-------|
| Initial Access | Drive-by Compromise | T1189 | Watering-hole via hijacked Plerdy analytics script on thousands of Ukrainian sites; also direct lookalike domains |
| Initial Access | Supply Chain Compromise: Software Supply Chain | T1195.002 | Plerdy SEO Tracker script (a.plerdy[.]com) injected with malicious JS fingerprinting gate; active August 27 – September 3, 2026 |
| Execution | Exploitation for Client Execution | T1203 | Zero-click CVE chains exploit mobile browsers without user interaction beyond page visit |
| Collection | Data from Local System | T1005 | AndroSnitch reads Chrome cookie databases and system Wi-Fi password storage |
| Credential Access | Credentials from Web Browsers | T1555.003 | AndroSnitch exfiltrates Chrome cookie DB from Android devices |
| Defense Evasion | Virtualization/Sandbox Evasion | T1497 | JavaScript fingerprinting gate checks device type, platform, browser version before serving exploit; sandbox visitors receive benign content |

---

## 3. Malware & Tools

| Name | Platform | Description |
|------|----------|-------------|
| DarkSword | iOS | Exploit kit targeting iOS 18.5 via 5-stage CVE chain (CVE-2026-20700 → CVE-2025-14174 → CVE-2025-43529 → CVE-2025-43510 → CVE-2025-43520); in-memory payload, no persistence; device must revisit site to re-infect after reboot; previously attributed to PARS Defense / UNC6748 / UNC6353 |
| AndroSnitch | Android | In-memory Android payload dropped via CVE-2026-3910 + CVE-2025-27038 on Chrome 139-145 (excluding 143); steals Chrome cookie databases and Wi-Fi passwords; no persistence (clears on reboot); SHA256: `387a7fb768db1350a9788d9704e7a72abe07152734e0ff026af72b417e36268c` |

---

## 4. Threat Actor / Campaign Attribution

**Threat Actor:** APT29 (SVR, Cozy Bear, Midnight Blizzard, IRON RITUAL)  
**Confidence:** Moderate-to-high  
**Campaign Name:** Poisoned Source  

APT29 (Russian Foreign Intelligence Service SVR) is attributed to the Poisoned Source campaign based on infrastructure overlaps, TTPs consistent with prior APT29 mobile-targeting operations (CaptiveCrunch, RedFlick), and the targeting profile focused on Ukrainian government and civil society organizations. The campaign exploited the Plerdy SEO Tracker analytics JavaScript (a.plerdy[.]com), widely deployed across Ukrainian websites, as a supply chain vector. The script was backdoored to serve a JavaScript fingerprinting gate that silently profiled visiting mobile devices and routed iOS and Android users to separate zero-click exploit chains. The iOS DarkSword exploit kit had previously appeared in campaigns attributed to PARS Defense (UNC6748/UNC6353), suggesting possible tool sharing or procurement by APT29.

**Campaign timeline:**
- **August 27 – September 3, 2026:** Plerdy script backdoored; thousands of Ukrainian sites serving malicious JS
- **September 3, 2026:** Plerdy removes malicious injection after notification
- **Post-September 3, 2026:** Watering-hole activity continues via lookalike domains (`theowo[.]club`, `america250[.]holiday`, etc.)
- **November 4, 2026:** Sekoia publishes public report

**Primary targets:** Ukrainian government agencies, civil society organizations, media outlets; broader Ukrainian internet users as collateral

---

## 5. Splunk Detection Searches

### 5.1 DNS Queries to Poisoned Source Watering-Hole Domains

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query IN ("theowo.club","*.theowo.club",
                      "america250.holiday","*.america250.holiday",
                      "static.flux-telemetry.com","*.flux-telemetry.com",
                      "adsprism-stat.com","*.adsprism-stat.com")
  by DNS.src DNS.query DNS.record_type DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| where risk_score >= 75
| table firstTime lastTime src query record_type answer risk_score
```

### 5.2 Network Connections to Poisoned Source Infrastructure

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_host IN ("theowo.club","america250.holiday",
                                   "static.flux-telemetry.com","adsprism-stat.com")
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.dest_port
     All_Traffic.app All_Traffic.user
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| where risk_score >= 75
| table firstTime lastTime src dest dest_host dest_port app user risk_score
```

### 5.3 Proxy / Web Logs — Plerdy Script Served from Non-Plerdy Domain

Detects browsers loading a resource named `plerdy` or `pler` from a domain other than `plerdy.com`, which may indicate the script was cached and re-served by a compromised CDN or attacker-controlled domain.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where (Web.uri_path="*plerdy*" OR Web.uri_path="*pler*")
    AND NOT Web.dest="*.plerdy.com"
    AND Web.http_method="GET"
  by Web.src Web.dest Web.uri_path Web.user_agent Web.http_method Web.status
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| where risk_score >= 50
| table firstTime lastTime src dest uri_path user_agent http_method status risk_score
```

### 5.4 AndroSnitch Hash Detection (Mobile Device Management / EDR)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Endpoint.Filesystem.file_hash="387a7fb768db1350a9788d9704e7a72abe07152734e0ff026af72b417e36268c"
  by Endpoint.Filesystem.dest Endpoint.Filesystem.user Endpoint.Filesystem.file_name
     Endpoint.Filesystem.file_path Endpoint.Filesystem.file_hash
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| where risk_score >= 75
| table firstTime lastTime dest user file_name file_path file_hash risk_score
```

---

## 6. Executive Summary

Sekoia published the Poisoned Source report on November 4, 2026, disclosing an APT29 (SVR) campaign that backdoored the Plerdy SEO Tracker analytics JavaScript between August 27 and September 3, 2026. Plerdy is embedded on thousands of Ukrainian websites, making this a high-impact supply chain watering hole. The injected script profiled visiting mobile devices and silently routed iOS and Android visitors to separate zero-click exploit chains: the DarkSword kit (5 CVEs targeting iOS 18.5) and a Chrome exploit chain (CVE-2026-3910 + CVE-2025-27038) delivering the AndroSnitch infostealer. Neither payload is persistent — a device reboot clears the infection — but AndroSnitch exfiltrates Chrome cookies and Wi-Fi passwords during its in-memory window. Post-September 3 activity continues via lookalike watering-hole domains. Defenders should block the four newly identified domains, hunt DNS/proxy logs for connections to these domains, and check MDM telemetry for the AndroSnitch hash. The technique of hijacking a widely-deployed third-party analytics script as a delivery vector is both high-reach and difficult to detect without supply chain integrity monitoring.
