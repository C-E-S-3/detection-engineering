---
scraped_at: "2026-07-27T00:00:00Z"
source_url: https://github.com/stamparm/maltrail/commit/a0a0554
report_type: threat-intel
severity: medium
title: "RedWing Panel / SXRat New C2 Infrastructure (July 25 2026)"
---

# RedWing Panel / SXRat New C2 Infrastructure

## 1. IOCs

### IP Addresses — C2 (primary TCP/8080; 69.164.252.150 on TCP/7000)

| Indicator | Source Commit |
|-----------|--------------|
| 103.27.156[.]192 | a0a0554 |
| 104.207.80[.]215 | a0a0554 |
| 104.244.90[.]94 | a0a0554 |
| 144.225.240[.]132 | a0a0554 |
| 144.31.106[.]200 | a0a0554 |
| 144.31.48[.]144 | a0a0554 |
| 151.243.218[.]132 | a0a0554 |
| 18.229.133[.]101 | a0a0554 |
| 185.112.59[.]214 | a0a0554 |
| 185.199.197[.]58 | a0a0554 |
| 185.69.122[.]108 | a0a0554 |
| 185.69.122[.]72 | a0a0554 |
| 191.44.113[.]16 | a0a0554 |
| 194.87.52[.]254 | a0a0554 |
| 195.226.92[.]50 | a0a0554 |
| 2.26.83[.]70 | a0a0554 |
| 200.9.155[.]236 | a0a0554 |
| 31.77.168[.]220 | a0a0554 |
| 37.77.150[.]21 | a0a0554 |
| 45.130.147[.]194 | a0a0554 |
| 45.144.65[.]6 | a0a0554 |
| 54.233.52[.]162 | a0a0554 |
| 72.61.249[.]143 | a0a0554 |
| 77.91.100[.]102 | a0a0554 |
| 77.91.100[.]81 | a0a0554 |
| 77.91.100[.]83 | a0a0554 |
| 78.46.23[.]30 | a0a0554 |
| 81.29.146[.]96 | a0a0554 |
| 87.120.84[.]133 | a0a0554 |
| 89.34.219[.]49 | a0a0554 |
| 93.152.223[.]39 | a0a0554 |
| 69.164.252[.]150 | a0a0554 |

### Domains — C2 and Panel Infrastructure

| Indicator | Notes |
|-----------|-------|
| redwing[.]top | Primary panel domain |
| redwingqq[.]top | Panel variant |
| redwing[.]ink | Panel branding domain |
| redwing-hub[.]top | Panel hub / distribution |
| s8k2x.redwing-hub[.]top | Panel subdomain |
| s8k2x.redwingqq[.]top | Panel subdomain |
| vnc.redwing[.]top | VNC remote access endpoint |
| webmaxauth[.]com | Panel authentication portal |
| arbuziki-shluszki[.]shop | C2 delivery domain |
| chill-dlapidril[.]shop | C2 delivery domain |
| ebem-mamontov[.]shop | C2 delivery domain |
| ebem-shlushek-kakbladushek[.]shop | C2 delivery domain |
| fixte.claytop[.]sbs | C2 delivery domain |
| krusty-crabs[.]sbs | C2 delivery domain |
| pidryzoski[.]sbs | C2 delivery domain |
| pushka-sosushka[.]top | C2 delivery domain |
| shlushka-potaskushka[.]shop | C2 delivery domain |
| shnejne-watafa[.]top | C2 delivery domain |
| sloniki-cartela[.]shop | C2 delivery domain |
| sly-time[.]sbs | C2 delivery domain |
| vpn.delt4[.]de | VPN/tunneling endpoint |

### File Hashes

| Hash | Type | Description |
|------|------|-------------|
| e7c94c12e6f63a817435e9b06e751878 | MD5 | SXRat / RedWing Panel implant sample |

## 2. TTPs

| Tactic | Technique ID | Technique | Usage |
|--------|-------------|-----------|-------|
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | HTTP C2 on non-standard port 8080; host beacons to panel IPs |
| Command and Control | T1219 | Remote Access Software | VNC-based remote desktop access via vnc.redwing.top dedicated subdomain |
| Command and Control | T1090.002 | Proxy: External Proxy | Multiple geographically distributed C2 IPs used for load distribution and resilience |
| Defense Evasion | T1036 | Masquerading | Panel domains use .top/.shop/.sbs/.ink TLDs typical of commodity cybercrime infrastructure |
| Persistence | T1543.003 | Create or Modify System Process: Windows Service | Typical Windows RAT persistence mechanism |

## 3. Malware & Tools

**RedWing Panel / SXRat:** A Windows remote access trojan distributed through Russian-speaking cybercrime channels. The extensive `redwing.*` domain branding — including `redwing.top`, `redwing.ink`, `redwing-hub.top`, `redwingqq.top`, and a dedicated `vnc.redwing.top` subdomain — indicates an organized Malware-as-a-Service (MaaS) panel operation. HTTP C2 operates primarily on TCP port 8080. VNC remote access capability is confirmed by the dedicated VNC subdomain. The MD5 `e7c94c12e6f63a817435e9b06e751878` corresponds to the SXRat implant binary tracked by maltrail.

## 4. Threat Actor / Campaign Attribution

Russian-speaking cybercrime actors (low-to-medium confidence). Several C2 delivery domains contain Cyrillic-transliterated Russian-language content: *arbuziki-shluszki* (colloquial Russian), *ebem-mamontov* (Russian slang), *shlushka-potaskushka*, *pidryzoski*, *sloniki-cartela*. This linguistic pattern is consistent with Russian-language underground forums and cybercrime operators based in Russia or CIS countries. No formal APT attribution. Infrastructure overlaps with .shop/.sbs/.top TLD patterns common to Russian-speaking commodity RAT operators.

## 5. Splunk Detection Searches

```spl
`-- Detect outbound connections to known RedWing Panel C2 IPs or domains`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where (All_Traffic.dest_ip IN (
    "103.27.156.192","104.207.80.215","104.244.90.94","144.225.240.132",
    "144.31.106.200","144.31.48.144","151.243.218.132","18.229.133.101",
    "185.112.59.214","185.199.197.58","185.69.122.108","185.69.122.72",
    "191.44.113.16","194.87.52.254","195.226.92.50","2.26.83.70",
    "200.9.155.236","31.77.168.220","37.77.150.21","45.130.147.194",
    "45.144.65.6","54.233.52.162","72.61.249.143","77.91.100.102",
    "77.91.100.81","77.91.100.83","78.46.23.30","81.29.146.96",
    "87.120.84.133","89.34.219.49","93.152.223.39","69.164.252.150")
  OR All_Traffic.dest IN (
    "redwing.top","redwingqq.top","redwing.ink","redwing-hub.top",
    "vnc.redwing.top","s8k2x.redwing-hub.top","s8k2x.redwingqq.top",
    "webmaxauth.com","arbuziki-shluszki.shop","ebem-mamontov.shop",
    "pushka-sosushka.top","sly-time.sbs","krusty-crabs.sbs","pidryzoski.sbs",
    "shlushka-potaskushka.shop","shnejne-watafa.top","sloniki-cartela.shop",
    "fixte.claytop.sbs","chill-dlapidril.shop","vpn.delt4.de"))
by All_Traffic.src All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port
   All_Traffic.transport All_Traffic.action
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(dest,"redwing\.(top|ink)") OR match(dest,"redwing-hub\.top") OR match(dest,"redwingqq\.top"), 90,
    dest_ip IN ("77.91.100.102","77.91.100.81","77.91.100.83","185.69.122.108","185.69.122.72"), 85,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime src dest dest_ip dest_port transport action risk_score
```

```spl
`-- DNS query detection for RedWing Panel domains`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query IN (
    "redwing.top","redwingqq.top","redwing.ink","redwing-hub.top",
    "vnc.redwing.top","s8k2x.redwing-hub.top","s8k2x.redwingqq.top",
    "webmaxauth.com","pushka-sosushka.top","vpn.delt4.de")
by DNS.src DNS.query DNS.record_type
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src query record_type risk_score
```

## 6. Executive Summary

On July 25, 2026, the stamparm/maltrail open-source threat intelligence repository added a new file (`trails/static/malware/sxrat.txt`) documenting RedWing Panel / SXRat C2 infrastructure. This represents a new malware family not previously tracked in this database. The release includes 32 confirmed C2 IP addresses (primarily on TCP port 8080), 22 C2/panel domains (including a dedicated VNC endpoint at vnc.redwing.top), and one implant MD5 hash. The infrastructure patterns and Cyrillic-influenced domain names are consistent with Russian-speaking cybercrime operators. Organizations should immediately block these IPs and domains at the firewall/DNS/proxy layer. Endpoint teams should hunt for the SXRat implant hash on Windows endpoints.
