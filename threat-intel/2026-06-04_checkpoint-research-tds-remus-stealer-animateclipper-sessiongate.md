---
scraped_at: 2026-06-09T00:00:00Z
source_url: https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/
report_type: threat-intel
severity: high
title: "Impersonation, Click Hijacking, and TDS: Inside a Malware Distribution Ecosystem — Remus Stealer, AnimateClipper, and SessionGate"
---

## 1. IOCs

### Domains
| Indicator | Role |
|-----------|------|
| asper1.freeddns.org | Remus Stealer C2 / payload staging |
| guiformat.com | TDS infrastructure / staging layer |
| cheapoca.biz | Remus Stealer C2 (also cheapoca.biz:5003) |

### IP Addresses
| Indicator | Role |
|-----------|------|
| 165.22.170.129 | TDS / payload delivery server (DigitalOcean) |

### File Hashes
| Hash | Type | Description |
|------|------|-------------|
| 48385492b6518cb2f3adcfd4a49c065ba960bdc617817068bd5faeb493d3f2db | SHA256 | Remus Stealer sample (YARA-referenced) |

### Other Indicators
- First public MaaS listing for "Remus": Russian-language underground forum, 2026-02-12
- TDS fingerprinting uses CloudFront-hosted JavaScript staging layer on download button clicks
- Known impersonated tools: Ghidra (NSA), dnSpy (.NET debugger), SpiderFoot (OSINT framework)

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1189 | Drive-by Compromise | 100+ fake sites impersonating Ghidra, dnSpy, SpiderFoot rank highly in Google search; clicking the download button triggers TDS routing |
| Initial Access | T1608.006 | Stage Capabilities: SEO Poisoning | Attacker-controlled sites boosted via ad networks and SEO to appear above legitimate tool sites in search results |
| Defense Evasion | T1027 | Obfuscated Files or Information | SessionGate multi-stage loader uses heavy obfuscation and extensive anti-analysis, making final payload extraction extremely difficult |
| Defense Evasion | T1497 | Virtualization/Sandbox Evasion | TDS enforces anti-bot, anti-analysis logic, VPN/datacenter filtering, and first-visit state gating before delivering payload |
| Credential Access | T1555.003 | Credentials from Web Browsers | Remus Stealer exfiltrates saved credentials from 20+ browsers and hundreds of extensions including crypto wallets, 2FA tools, password managers |
| Collection | T1539 | Steal Web Session Cookie | Remus Stealer targets browser session cookies across all major browsers |
| Impact | T1657 | Financial Theft | AnimateClipper hijacks cryptocurrency clipboard transactions across 20+ blockchain ecosystems (Bitcoin, Ethereum, etc.) |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | C2 beacons over HTTP to asper1.freeddns.org, cheapoca.biz:5003, and 165.22.170.129 |

## 3. Malware & Tools

| Name | Type | Description |
|------|------|-------------|
| Remus Stealer | Information Stealer | Newly emerged Windows infostealer (first listed Feb 12, 2026 on Russian underground); sweeps 20+ browsers, 100s of browser extensions, crypto wallet files, 2FA apps, and password manager vaults; HTTP C2 to cheapoca.biz:5003 and asper1.freeddns.org; first public write-up credits YARA hash 48385492... |
| AnimateClipper | Cryptocurrency Clipper | Clipboard hijacker capable of silently replacing cryptocurrency wallet addresses across 20+ blockchain ecosystems (BTC, ETH, SOL, and others) during copy/paste operations |
| SessionGate | Multi-Stage Loader | Previously unknown Windows loader; heavy string obfuscation and anti-analysis (anti-debugging, anti-VM, timing checks); staged delivery through CloudFront JS layer; acts as first-stage downloader for Remus Stealer and AnimateClipper |

## 4. Threat Actor / Campaign Attribution

| Attribute | Detail |
|-----------|--------|
| Actor | Unknown / unattributed |
| Motivation | Financial — credential theft and cryptocurrency theft |
| First seen | February 12, 2026 (Remus Stealer MaaS listing on Russian-language forum) |
| Geographic targeting | Global; highest victim visibility in Turkey, Poland, Brazil, Germany, France, Russia, and the UK |
| Sector targeting | Software developers, security researchers, penetration testers (users of Ghidra, dnSpy, SpiderFoot) |
| Infrastructure | CloudFront JS staging, DigitalOcean TDS server (165.22.170.129), DDNS (asper1.freeddns.org) |
| Distribution scale | 100+ impersonation sites identified impersonating legitimate open-source security and developer tools |

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where (All_Traffic.dest="165.22.170.129")
     OR (All_Traffic.dest_host IN ("asper1.freeddns.org","guiformat.com","cheapoca.biz"))
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    dest="165.22.170.129" OR dest_host="asper1.freeddns.org" OR dest_host="cheapoca.biz", 85,
    dest_host="guiformat.com", 70,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime src dest dest_host dest_port risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query IN ("asper1.freeddns.org","guiformat.com","cheapoca.biz","asper1.freeddns.org")
  by DNS.src DNS.query DNS.record_type DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime src query record_type answer risk_score
```

```spl
index=* (src_ip="165.22.170.129" OR dest_ip="165.22.170.129"
    OR url="*asper1.freeddns.org*" OR url="*cheapoca.biz*" OR url="*guiformat.com*")
| eval risk_score=85
| table _time host src_ip dest_ip url user risk_score
```

## 6. Executive Summary

Check Point Research documented a large-scale malware distribution ecosystem active in early June 2026 that impersonates more than 100 legitimate open-source security and developer tools — including NSA's Ghidra reverse-engineering suite, the .NET debugger dnSpy, and the OSINT framework SpiderFoot — via SEO-poisoned websites that rank above authentic download pages in Google search results.

Victims who click a download link are silently routed through a CloudFront-hosted JavaScript fingerprinting layer that acts as a Traffic Distribution System (TDS). The TDS enforces strict visitor gating: first-visit state tracking, mandatory click confirmation, anti-bot/anti-analysis logic, VPN and datacenter IP filtering, and per-victim frequency capping. Only qualifying visitors receive the malicious payload.

The campaign delivers three distinct malware families: **Remus Stealer**, a newly emerged infostealer first sold on a Russian-language underground forum in February 2026 that harvests credentials from 20+ browsers, hundreds of extensions, and cryptocurrency wallets; **AnimateClipper**, a clipboard hijacker targeting 20+ blockchain ecosystems; and **SessionGate**, a previously unknown obfuscated multi-stage loader that acts as the deployment vehicle for the other payloads.

Security teams and developers are at particularly high risk because the lure sites impersonate tools used exclusively by security practitioners and software engineers. The campaign is consistent with financially motivated threat actors targeting high-value developer workstations where cloud credentials, CI/CD tokens, and cryptocurrency wallets are likely to be present.
