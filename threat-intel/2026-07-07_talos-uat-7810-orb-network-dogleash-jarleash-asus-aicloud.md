---
scraped_at: "2026-07-07T00:00:00Z"
source_url: "https://blog.talosintelligence.com/uat-7810/"
report_type: threat-intel
severity: high
title: "UAT-7810 (China-Nexus): ORB Network Expansion with DOGLEASH/JARLEASH/LONGLEASH Malware via ASUS AiCloud CVE-2025-2492"
---

# UAT-7810 (China-Nexus): ORB Network Expansion with DOGLEASH/JARLEASH/LONGLEASH Malware via ASUS AiCloud CVE-2025-2492

**Source:** Cisco Talos Intelligence Group  
**Published:** 2026-07-06  
**Severity:** High  
**Tactic:** Initial Access (TA0001), Persistence (TA0003), Command and Control (TA0011)

---

## 1. IOCs

### IP Addresses (C2 Infrastructure)

| Indicator | Type | Notes |
|-----------|------|-------|
| `194.233.92.26` | IPv4 C2 | UAT-7810 ORB relay node; HTTP C2 on ports 8088 and 2222 |
| `217.15.160.247` | IPv4 C2 | UAT-7810 ORB relay node; HTTP C2 on ports 8088, 2222, and 99 |
| `217.15.164.147` | IPv4 C2 | UAT-7810 ORB relay node; HTTP C2 on ports 8088, 2222, and 99 |
| `95.182.100.231` | IPv4 C2 | UAT-7810 ORB relay node; HTTP C2 on port 2222 |

### C2 URLs

| URL | Notes |
|-----|-------|
| `http://194.233.92.26:8088/` | UAT-7810 C2 |
| `http://194.233.92.26:2222/` | UAT-7810 C2 |
| `http://217.15.160.247:8088/` | UAT-7810 C2 |
| `http://217.15.160.247:2222/` | UAT-7810 C2 |
| `http://217.15.160.247:99/` | UAT-7810 C2 |
| `http://217.15.164.147:8088/` | UAT-7810 C2 |
| `http://217.15.164.147:2222/` | UAT-7810 C2 |
| `http://217.15.164.147:99/` | UAT-7810 C2 |
| `http://95.182.100.231:2222/` | UAT-7810 C2 |

### File Hashes

#### LONGLEASH (1 sample)

| SHA-256 | Malware Family |
|---------|----------------|
| `755fcee1337a252203002ecfdf673a08cfadeda8d738bef2d518a08e0626aa4f` | LONGLEASH |

#### LEASHTEST (1 sample)

| SHA-256 | Malware Family |
|---------|----------------|
| `1b5649b479fd625de5c8120873644b5eb669cc89cd504582c18e0ae350fd8823` | LEASHTEST |

#### JARLEASH (4 samples)

| SHA-256 | Malware Family |
|---------|----------------|
| `e799d72929d7ccc7f6b6109742b8cc482838303207efc989543b6e1ca6d16e9c` | JARLEASH |
| `3b89d183eb014e29d9d0d4e45fc2b784a7fcfcf31dd48fd3bde30f8d956383d1` | JARLEASH |
| `324d95024fc8da5c92b5a1f4825aed5a2a91c9ca8fb6aa52abb332a4c9cf4257` | JARLEASH |
| `bafba443170e54ef7fd431ce7f1b5e202719f3fd022e4ef70788904f574d2cdf` | JARLEASH |

#### DOGLEASH (21 samples)

| SHA-256 | Malware Family |
|---------|----------------|
| `604b53f87d6c070bf387e80c70a6df8d272fa3fc143148d41f13e59d52ab1f13` | DOGLEASH |
| `c92541f273eeb576d39235d0a5c6f18f2574b132a1022598edfa38065783ab98` | DOGLEASH |
| `29c7fccc6ef8cbfe4da9a169c7c74bacaea1fb515a1fddef91ab1b1522f76e4c` | DOGLEASH |
| `425bf771c8c9f740b1ae9803dcb4fd45af4d6a6f171fcc72fc7d511095ca82ce` | DOGLEASH |
| `ac8eae94d27122f4751bc96d9ea52d30000b7ca37569a2291b2710824ca3396f` | DOGLEASH |
| `dc4f25b2247cfdd6fc96848db30a178baa4419a4c854e86e315b465836102d14` | DOGLEASH |
| `3878dd5c8eba1e5b53ab2e07e7b5482e95a3fd3e98268bcd7861318bc9902376` | DOGLEASH |
| `9b9e0e5a1eb469b8d20dc23351e08ff5d5731e1cedce0ddee9bbd00a76217f13` | DOGLEASH |
| `57bdab2ba4b05ec0338c06632599393d5b14227f31a43fe950ea8fdd47428715` | DOGLEASH |
| `b8d247fd1fb85d24a17afeec3815906dfbcdc5359647910b4a153900ec999a0f` | DOGLEASH |
| `5e225ea2648a8cba0fd94ec7fd8ce5315f5d0cc2922bafc9db3c8c41280e917c` | DOGLEASH |
| `d5cf7315186a78ab6a7475c338bdf101bc6461930aaa7a012a02cf93f347c207` | DOGLEASH |
| `dd0fc1a88180fde8367bec7086f99294f36b8332f12994293139ed532d2ebbac` | DOGLEASH |
| `5c3f190571645c4641dcff2c07a4c3ab9acad06aa9607350a385729d8d6139f1` | DOGLEASH |
| `323c3a91be60ebc3e06e942bad04899a15911cea23269e43d07829164b2ce5d4` | DOGLEASH |
| `880425fee707e9f42e0b8d60119ed639b1ad506ea29877d126bdebce379cd229` | DOGLEASH |
| `e5d2de8ae98579bfb940290f60e59a502b3065345aaf765456387989c0488b20` | DOGLEASH |
| `2e0e43776e2e1a37d882a1b2ebb7d337ee88950177e43831dae645a367824feb` | DOGLEASH |
| `b5969636eec376ad6c3ece2202b1722219955638e09b6f96d4cfc0598d3b1890` | DOGLEASH |
| `1660536f448b8b9f086ce9ea3ce4e9deefc59a76711ea53ee6d8f08fc8c1bb99` | DOGLEASH |
| `65feba2c971c214e71303ad2e0fbf62b45ebcaa784cbf3d0dab62786cb4c0469` | DOGLEASH |

### CVEs Exploited

| CVE | Product | CVSS | Description |
|-----|---------|------|-------------|
| CVE-2025-2492 | ASUS AiCloud | 9.2 | Authentication bypass (CWE-288) — unauthenticated remote access to AiCloud-enabled routers |
| CVE-2023-25717 | Ruckus access points | N/A | Remote code execution |
| CVE-2020-22653 | SOHO router (various) | N/A | Router vulnerability used for ORB node recruitment |
| CVE-2020-22658 | SOHO router (various) | N/A | Router vulnerability used for ORB node recruitment |

---

## 2. TTPs

| MITRE Tactic | Tactic ID | Technique | Technique ID | Usage |
|--------------|-----------|-----------|--------------|-------|
| Initial Access | TA0001 | Exploit Public-Facing Application | T1190 | CVE-2025-2492 on ASUS AiCloud routers; CVE-2023-25717 on Ruckus APs; older CVEs on SOHO routers |
| Persistence | TA0003 | Boot or Logon Autostart Execution: RC Scripts | T1037.004 | JARLEASH startup script installs DOGLEASH/SHORTLEASH for persistence across reboots |
| Command and Control | TA0011 | Proxy: Multi-hop Proxy | T1090.003 | Compromised SOHO/enterprise routers configured as ORB relay nodes; traffic routed through multiple hop points to obscure true origin of espionage operations |
| Command and Control | TA0011 | Encrypted Channel | T1573 | Malware family communications use encrypted channels to C2 infrastructure |
| Defense Evasion | TA0005 | Proxy | T1090 | ORB network architecture hides attacker's true infrastructure behind layers of compromised legitimate routers |
| Collection | TA0009 | Data from Network Shared Drive | T1039 | ORB nodes relay espionage collection traffic from downstream victim networks |

---

## 3. Malware & Tools

### DOGLEASH

- **Type:** Router/edge device implant — ORB relay agent
- **Platform:** Linux (ELF); targets SOHO and enterprise routers/APs
- **Role:** Primary ORB relay node implant; receives and forwards traffic from other compromised nodes in the relay chain
- **21 samples** across multiple appliance architectures

### JARLEASH

- **Type:** Startup/persistence script
- **Role:** Installs and maintains DOGLEASH/SHORTLEASH across reboots; drops RC startup scripts to survive device reboot
- **Developer artifact:** Mandarin developer notes found in JARLEASH startup scripts, supporting China-nexus attribution
- **4 samples**

### LONGLEASH

- **Type:** Router/edge device implant
- **Platform:** Linux (ELF)
- **Role:** Extended persistence/capability module; relationship to DOGLEASH under investigation
- **1 sample**

### LEASHTEST

- **Type:** Testing/validation tool
- **Role:** Likely a developer/operator testing tool for validating implant functionality on target devices
- **1 sample**

### SHORTLEASH (prior disclosure)

- **Type:** Lightweight ORB relay implant (previously documented by SecurityScorecard, June 2025)
- **Role:** Initial ORB node implant; lighter than DOGLEASH; used in earlier LapDogs/SHORTLEASH campaign phases

---

## 4. Threat Actor Profile

| Attribute | Detail |
|-----------|--------|
| Tracking Name | UAT-7810 (Cisco Talos) |
| Related Tracking | UAT-5918 (Talos overlap); LapDogs/SHORTLEASH campaign (SecurityScorecard, June 2025) |
| Suspected Origin | China-nexus |
| Attribution Basis | Mandarin developer notes in JARLEASH startup scripts; overlapping infrastructure with UAT-5918; TTP alignment with known Chinese ORB network operations |
| Motivation | Espionage — ORB network construction for intelligence collection and attribution obfuscation |
| Target | SOHO routers, enterprise edge devices, ASUS AiCloud-enabled routers, Ruckus access points |
| Method | Exploit unpatched SOHO/enterprise edge devices to build ORB relay infrastructure; recruited nodes relay C2 traffic from targeted victim networks |
| First Seen | Connected to LapDogs campaign (SecurityScorecard June 2025); UAT-7810 designation new to July 2026 Talos report |

---

## 5. Splunk Detection Searches

### Search 1 — Network Traffic: Outbound Connections to UAT-7810 C2 IPs on Non-Standard Ports

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest IN ("194.233.92.26","217.15.160.247","217.15.164.147","95.182.100.231")
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.bytes_out
| `drop_dm_object_name(All_Traffic)`
| eval risk_score=100
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src dest dest_port bytes_out risk_score
```

Detects any connection to confirmed UAT-7810 ORB relay infrastructure.

### Search 2 — Network Traffic: Non-Standard Port HTTP Connections to ORB C2 Port Patterns

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_port IN (2222,8088,99)
    AND All_Traffic.action="allowed"
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.bytes_out
| `drop_dm_object_name(All_Traffic)`
| where NOT dest IN ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")
| stats count, dc(dest) as unique_dests, values(dest) as destinations
  by src, dest_port
| where count >= 3
| eval risk_score=case(dest_port=2222 AND unique_dests > 1, 75, dest_port=8088, 65, 1=1, 55)
| where risk_score >= 55
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src dest_port count unique_dests destinations risk_score
```

Detects persistent outbound HTTP-like connections on ports 2222, 8088, and 99 — the specific ports used by UAT-7810's ORB relay C2 protocol. Legitimate use of port 2222 (alternative SSH) and 99 (rare) from endpoints is uncommon.

### Search 3 — Web: HTTP Connections on Non-Standard Ports (UAT-7810 C2 Protocol Detection)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.dest_port IN (2222,8088,99)
  by Web.src Web.dest Web.dest_port Web.url Web.http_method Web.status
| `drop_dm_object_name(Web)`
| where NOT (dest LIKE "10.%" OR dest LIKE "172.16.%" OR dest LIKE "192.168.%")
| eval risk_score=75
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src dest dest_port url http_method status risk_score
```

Detects HTTP traffic on ports 2222, 8088, and 99 — UAT-7810's ORB relay C2 communication pattern. Note that HTTP on port 2222 is highly unusual in enterprise environments.

---

## 6. Executive Summary

On July 6, 2026, Cisco Talos published research disclosing **UAT-7810**, a China-nexus APT that has expanded the SHORTLEASH/LapDogs ORB network campaign (previously documented by SecurityScorecard in June 2025) with four new malware families. UAT-7810 exploits unpatched SOHO and enterprise edge devices — primarily ASUS AiCloud routers (CVE-2025-2492, CVSS 9.2), Ruckus access points (CVE-2023-25717), and older router vulnerabilities — to build **Operational Relay Box (ORB)** networks that proxy espionage traffic through layers of legitimate-looking infrastructure.

The four new malware families are:
- **DOGLEASH** (21 samples) — primary ORB relay agent deployed on compromised routers
- **JARLEASH** (4 samples) — persistence startup script; contains Mandarin developer notes supporting China attribution
- **LONGLEASH** (1 sample) — extended implant module
- **LEASHTEST** (1 sample) — likely developer/operator testing tool

Four C2 IPs were disclosed with specific port combinations (8088, 2222, 99) used for ORB relay communications.

ORB networks are a significant defensive challenge: compromised legitimate SOHO routers in victim-adjacent network ranges proxy attack traffic, making source attribution difficult and geographic blocking ineffective. Defenders should prioritize blocking the disclosed C2 IPs, monitoring for HTTP traffic on ports 2222/8088/99, and patching ASUS AiCloud-enabled devices for CVE-2025-2492.

---

## References

- [Cisco Talos — UAT-7810 ORB Network (2026-07-06)](https://blog.talosintelligence.com/uat-7810/)
- [Cisco Talos IOC GitHub — July 2026](https://github.com/Cisco-Talos/IOCs/tree/main/2026/07)
- [SecurityScorecard — LapDogs/SHORTLEASH Campaign (2025-06)](https://securityscorecard.com/research/lapdog-proxy-network/)
- [NVD — CVE-2025-2492 (ASUS AiCloud)](https://nvd.nist.gov/vuln/detail/CVE-2025-2492)
- [MITRE ATT&CK — T1090.003: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003/)
- [MITRE ATT&CK — T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
