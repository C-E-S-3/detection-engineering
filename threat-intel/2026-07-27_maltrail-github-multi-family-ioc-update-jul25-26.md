---
scraped_at: "2026-07-27T00:00:00Z"
source_url: https://github.com/stamparm/maltrail
report_type: threat-intel
severity: medium
title: "Multi-Family IOC Update: UNC6691, SilverFox, Android NGate, FakeApp macOS, DoNot APT, BankBot (July 25-26 2026)"
---

# Multi-Family IOC Update: UNC6691, SilverFox, Android NGate, FakeApp macOS, DoNot APT, BankBot

Aggregated from stamparm/maltrail GitHub commits on July 25–26 2026. Covers six threat families with newly confirmed C2 and distribution infrastructure.

## 1. IOCs

### UNC6691 — New Domains (37) — Commit cabae1f, July 25 2026

UNC6691 is an uncategorized threat cluster tracked by Mandiant/GTIG. The domains follow a pattern of short random-looking 5-character alphanumeric `.com` names, consistent with registered infrastructure for phishing, credential harvesting, or as staging nodes. Three domains deviate from this pattern and suggest specific operational branding: `argvio.com`, `bitxhgj.com`, `neonflowmedia.vip`, `newsn.sbs`, `tnyyy.top`, `web3geam.top`, `energyl.shop`.

| Indicator |
|-----------|
| 1c5w8[.]com |
| 2b9t4[.]com |
| 2d8g1[.]com |
| 3g9w1[.]com |
| 4b7n2[.]com |
| 4qnz9[.]com |
| 4z8v5[.]com |
| 55pqx[.]com |
| 6m2p9[.]com |
| 7f2k4[.]com |
| 7p2k6[.]com |
| 8f3d7[.]com |
| argvio[.]com |
| bitxhgj[.]com |
| c6w2k[.]com |
| energyl[.]shop |
| f4m8t[.]com |
| j5km8[.]com |
| k2z8p[.]com |
| k3c8d[.]com |
| k4x9r[.]com |
| k8v4z[.]com |
| m1r6f[.]com |
| m6p3z[.]com |
| neonflowmedia[.]vip |
| newsn[.]sbs |
| p5z9q[.]com |
| q5z2d[.]com |
| t7n4z[.]com |
| tnyyy[.]top |
| v5n1c[.]com |
| w3d8z[.]com |
| w8c2k[.]com |
| web3geam[.]top |
| x4c8b[.]com |
| x9r4d[.]com |
| z4r8t[.]com |

---

### SilverFox — New Domains (20) — Commit 80868ff, July 26 2026

SilverFox is a Chinese-speaking credential-harvesting and phishing campaign family targeting online users with fake financial/investment and delivery lures. The domains below are newly registered/activated infrastructure.

| Indicator |
|-----------|
| agbwrbugerxr[.]top |
| chimaojiuye[.]com |
| ghteiurijyjly[.]shop |
| gi-dhl[.]live |
| gnrdlyonxw[.]top |
| ihezu[.]vip |
| jmzpw[.]vip |
| kjtuirhsa.eu[.]cc |
| mateuart[.]vip |
| nasjdbed[.]cc |
| nasjdbed[.]com |
| reelsessions[.]live |
| roney[.]live |
| staru[.]top |
| uituywergfds[.]shop |
| wqqxfhfnb.eu[.]cc |
| xianzhixingjiankang[.]top |
| ytireyebg[.]shop |
| zdgaery.web[.]id |
| zkehm[.]vip |

---

### Android NGate — New C2 Domains and IP — Commit c516a7c, July 26 2026

NGate is an Android banking trojan that relays NFC payment card data from a victim's device to an attacker-controlled device, enabling contactless payment fraud without physical card theft. The new C2 infrastructure is organized around the `cupworldcup.site` and `dashboardcloud.app` domains.

**Domains:**

| Indicator | Notes |
|-----------|-------|
| api.cupworldcup[.]site | NGate API endpoint |
| api.dashboardcloud[.]app | NGate API endpoint (secondary) |
| cupworldcup[.]site | NGate primary C2 domain |
| dashboardcloud[.]app | NGate C2 domain (secondary) |
| semprecardsecure[.]com | NGate distribution / lure domain |
| totalsecure-e5d.pages[.]dev | NGate Cloudflare Pages lure |
| web.cupworldcup[.]site | NGate web panel subdomain |
| ws.cupworldcup[.]site | NGate WebSocket C2 endpoint |

**IP:**

| Indicator | Port | Notes |
|-----------|------|-------|
| 181.214.221[.]30 | 3000 | NGate C2 server |

---

### FakeApp macOS — New Domains — Commits e811a8f (Jul 25) and 452279e (Jul 26)

A macOS-targeting fake application campaign delivering infostealers via trojanized macOS applications. The July 26 update is particularly focused on macOS (`flowmacos.shop`, `macappsworld.org`, `macelitepros.com`, `macnest.org`, `macslegacy.com`, `mactoolskit.com`, `macworkflows.com`). Domains use `.it.com`, `.cfd`, `.sbs`, and `.shop` TLDs.

**Selected domains (representative; full list in domain.csv):**

| Indicator |
|-----------|
| acergvje.it[.]com |
| cvmnrue.it[.]com |
| ditekjfh.it[.]com |
| drft5gh[.]cfd |
| dvnthrut.it[.]com |
| flowmacos[.]shop |
| gbvfehru.it[.]com |
| macappsworld[.]org |
| macelitepros[.]com |
| macnest[.]org |
| macslegacy[.]com |
| mactoolskit[.]com |
| macworkflows[.]com |
| redircet5[.]cfd |
| tbjfngdl.it[.]com |
| topmacfiles[.]sbs |
| winupdatehelper[.]online |

**IP:**

| Indicator | Notes |
|-----------|-------|
| 178.159.0[.]12 | FakeApp staging/C2 server |

**Hash:**

| Hash | Type | Notes |
|------|------|-------|
| 1618d761d9062db463e372b5bde1c595e13c701b881ccaa4fa6c26a409bc26cb | SHA-256 | FakeApp sample; referenced in maltrail commit e811a8f |

---

### Android BankBot — New IOCs — Commit e288835, July 25 2026

Android BankBot family update with new C2 server infrastructure. Targeting Android banking apps.

**IPs:**

| Indicator | Port |
|-----------|------|
| 151.247.22[.]25 | 8080 |
| 192.238.202[.]61 | 8080 |
| 72.60.77[.]146 | 8080/8081/8083 |
| 103.106.66[.]147 | 8080 |
| 91.219.237[.]105 | 8080 |

**Domains:**

| Indicator |
|-----------|
| api.roradar[.]io |
| roradar[.]io |
| tonflow[.]xyz |
| xyzzxyz[.]xyz |

---

### DoNot APT (APT-C-35 / StealJob) — New Domains — Commits 852605d (Jul 25), 32a2eaa (Jul 26)

DoNot Team (APT-C-35, StealJob) is an India-linked APT targeting entities in South Asia. New domains confirmed July 25–26 2026.

| Indicator |
|-----------|
| logshopperz[.]info |
| quickly21[.]com |
| virgology[.]info |

---

### Additional Single-Family Updates

**Vidar Stealer** (commit 7a652e1, July 26):

| Type | Indicator | Notes |
|------|-----------|-------|
| IP | 134.195.88[.]33 | Vidar C2, port 8443 |
| Domain | bascofinefood[.]cfd | Vidar C2 domain |

**Lumma Stealer** (commit e1539d7, July 25):

| Type | Indicator |
|------|-----------|
| Domain | milezcv[.]cyou |
| Domain | toolsep[.]biz |

**OceanLotus / APT32** (commit 88d4031, July 25):

| Type | Indicator | Notes |
|------|-----------|-------|
| Domain | 0b3l1sk[.]me | New OceanLotus C2; rotajakiro Linux backdoor attributed to APT32 |
| SHA-256 | d1cdeea8a081397632c0522476da2122f93c71cb14a36ad4e8d4351b3d65fd6d | rotajakiro ELF sample |

**SectopRAT** (commit e08789d, July 26):

| Type | Indicator | Notes |
|------|-----------|-------|
| IP | 178.16.55[.]227 | SectopRAT C2, port 9000 |

**ChaosRAT** (commit 39f4a20, July 25):

| Type | Indicator | Notes |
|------|-----------|-------|
| IP | 209.46.126[.]251 | ChaosRAT C2, ports 8080 and 8081 |

## 2. TTPs

| Tactic | Technique ID | Technique | Families |
|--------|-------------|-----------|---------|
| Command and Control | T1071.001 | Application Layer Protocol: Web | All families above |
| Command and Control | T1219 | Remote Access Software | Android NGate (NFC relay) |
| Initial Access | T1476 | Deliver Malicious App via Other Means | Android NGate, FakeApp macOS |
| Collection | T1430 | Location Tracking / NFC Data | Android NGate (NFC relay theft) |
| Defense Evasion | T1036 | Masquerading | FakeApp macOS (fake app branding) |
| Credential Access | T1417 | Input Capture (Mobile) | Android BankBot |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | Vidar, Lumma, SectopRAT |
| Collection | T1005 | Data from Local System | Vidar, Lumma, SectopRAT |

## 3. Malware & Tools

- **UNC6691:** Uncategorized Mandiant threat cluster; 37 new registered domains suggest active campaign build-out.
- **SilverFox:** Chinese-speaking credential-harvesting and financial fraud campaign; .vip/.live/.top TLD patterns consistent with prior waves.
- **Android NGate:** NFC relay banking trojan (ESET-documented); steals contactless payment credentials via malicious Android app; new `cupworldcup.site` C2 cluster.
- **FakeApp macOS:** macOS infostealer delivery via fake applications; July 26 wave explicitly targets macOS (`flowmacos`, `macappsworld`, `mactoolskit`) via .it.com bulk-registered domains.
- **Android BankBot:** Commodity Android banking trojan; credential overlay attacks on banking apps.
- **DoNot APT (APT-C-35, StealJob):** India-linked APT targeting Pakistan, Kashmir, and South Asian defense/government entities.
- **Vidar Stealer:** Commodity Windows infostealer; new `.cfd` TLD C2.
- **Lumma Stealer (LummaC2):** MaaS Windows infostealer with Telegram API bot exfiltration.
- **OceanLotus / APT32 (rotajakiro):** Vietnam-nexus APT; rotajakiro is a Linux backdoor with DNS tunneling.
- **SectopRAT (ArechClient2):** .NET Windows RAT with C2 reachable via raw TCP (port 9000).
- **ChaosRAT:** Multi-platform Go-based RAT; dual-port C2 on 8080/8081.

## 4. Threat Actor / Campaign Attribution

| Actor | Attribution | Confidence |
|-------|------------|-----------|
| UNC6691 | Uncategorized (Mandiant tracking) | High confidence in cluster attribution, actor origin unknown |
| SilverFox | Chinese-speaking cybercrime | Medium |
| Android NGate | Eastern European cybercrime (ESET) | Medium |
| FakeApp macOS | Unknown; commodity MaaS | Low |
| Android BankBot | Eastern European cybercrime | Low |
| DoNot APT / APT-C-35 | India-linked nation-state | High |
| Vidar | Russian-speaking MaaS | High |
| Lumma / LummaC2 | Russian-speaking MaaS | High |
| OceanLotus / APT32 | Vietnam SIGINT (Group G0050) | High |
| SectopRAT / ArechClient2 | Unknown cybercrime | Low |
| ChaosRAT | Unknown | Low |

## 5. Splunk Detection Searches

```spl
`-- DNS detection for UNC6691 infrastructure domains`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query IN (
    "argvio.com","bitxhgj.com","neonflowmedia.vip","newsn.sbs",
    "tnyyy.top","web3geam.top","energyl.shop","1c5w8.com","2b9t4.com",
    "2d8g1.com","3g9w1.com","4b7n2.com","4qnz9.com","4z8v5.com",
    "55pqx.com","6m2p9.com","7f2k4.com","7p2k6.com","8f3d7.com",
    "c6w2k.com","f4m8t.com","j5km8.com","k2z8p.com","k3c8d.com",
    "k4x9r.com","k8v4z.com","m1r6f.com","m6p3z.com","p5z9q.com",
    "q5z2d.com","t7n4z.com","v5n1c.com","w3d8z.com","w8c2k.com",
    "x4c8b.com","x9r4d.com","z4r8t.com")
by DNS.src DNS.query DNS.record_type
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=80
| table firstTime lastTime src query record_type risk_score
```

```spl
`-- Detect connections to Android NGate NFC relay C2 infrastructure`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where (All_Traffic.dest_ip="181.214.221.30"
  OR All_Traffic.dest IN (
    "cupworldcup.site","api.cupworldcup.site","ws.cupworldcup.site",
    "web.cupworldcup.site","dashboardcloud.app","api.dashboardcloud.app",
    "semprecardsecure.com"))
by All_Traffic.src All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port
   All_Traffic.transport All_Traffic.action
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime src dest dest_ip dest_port transport action risk_score
```

```spl
`-- Detect connections to multi-family C2 IPs (BankBot, ChaosRAT, SectopRAT, Vidar)`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_ip IN (
    "151.247.22.25","192.238.202.61","72.60.77.146","103.106.66.147",
    "91.219.237.105","209.46.126.251","178.16.55.227","134.195.88.33","178.159.0.12")
by All_Traffic.src All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port
   All_Traffic.transport All_Traffic.action
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=80
| table firstTime lastTime src dest dest_ip dest_port transport action risk_score
```

## 6. Executive Summary

On July 25–26, 2026, maltrail received updates for six distinct malware families. The most operationally significant is UNC6691, which saw 37 new domains added — a volume suggesting active campaign infrastructure deployment. FakeApp macOS added 46+ new domains targeting macOS users, with explicit Apple ecosystem branding. Android NGate received a new C2 cluster around `cupworldcup.site`. DoNot APT (India-linked) added three new domains. SilverFox (Chinese credential harvesting) expanded with 20 new domains. Smaller updates hit Vidar, Lumma, SectopRAT, ChaosRAT, and OceanLotus/APT32. All IOCs have been appended to the appropriate CSV files.
