---
scraped_at: 2026-06-11T06:30:00Z
source_url: https://www.lumen.com/blog/en-us/expanded-jdy-iot-and-soho-botnet-enables-rapid-vulnerability-exploitation
report_type: threat-intel
severity: high
title: "JDY Botnet Expands to 1,500+ SOHO/IoT Devices, Targets U.S. Military Networks with Rapid CVE Exploitation (Volt Typhoon / China-Nexus)"
---

# JDY Botnet Expands to 1,500+ SOHO/IoT Devices, Targets U.S. Military Networks with Rapid CVE Exploitation

Lumen Technologies' Black Lotus Labs published research on June 10, 2026 documenting a significant expansion of the **JDY botnet**, a China-state-linked covert network of compromised SOHO and IoT devices associated with the Volt Typhoon cluster. JDY has grown from approximately 650 active compromised devices in early 2024 to over 1,500 devices in mid-2026, with a focus on U.S. military-adjacent network reconnaissance and rapid exploitation of newly disclosed vulnerabilities — including scanning for CVE-2026-35616 (FortiClient EMS) within hours of public disclosure.

JDY was originally identified as a sub-cluster within the broader KV-botnet infrastructure. It is distinct from the KV-botnet's use as a proxy relay network: JDY is purpose-built as a high-performance distributed scanner and fingerprinting platform, tasked with discovering, mapping, and continuously tracking internet-exposed services at scale.

---

## 1. IOCs

### C2 Infrastructure
JDY's command-and-control architecture routes operator tasking through **Tor hidden services**. Lumen Black Lotus Labs maintains a continuously updated IOC list on their GitHub repository (linked in References). Specific C2 IP addresses are not published in this report to avoid blocking legitimate Tor infrastructure; monitor for botnet-consistent behavior from edge devices instead.

### Compromised Device Categories
Compromised devices span the following brands (MIPS/MIPS64/MIPSEL/MIPSEL64 architectures):

| Vendor | Device Type |
|--------|------------|
| Cisco | SOHO routers and switches |
| Araknis Networks | SOHO networking equipment |
| Mimosa Networks | Fixed wireless access points |
| Ubiquiti | SOHO routers and access points |
| DrayTek | SOHO routers and firewalls |
| Hikvision | IP cameras and NVRs |
| Linksys | SOHO routers |

### CVEs Actively Targeted by JDY Scanning
| CVE | Product | Notes |
|-----|---------|-------|
| CVE-2026-35616 | Fortinet FortiClient EMS | JDY scanned within hours of public disclosure; CVSS 9.1 pre-auth API bypass |
| Multiple N-day CVEs | Various SOHO/edge devices | JDY performs broad sweep of known SOHO appliance vulnerability patterns |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Resource Development | T1584.005 | Compromise Infrastructure: Botnet | JDY operators build and expand a SOHO/IoT botnet of 1,500+ compromised devices, refreshing it as devices are remediated or rebooted |
| Reconnaissance | T1595.001 | Active Scanning: Scanning IP Blocks | JDY performs high-volume TCP, UDP, SSL, and ICMP-assisted probing across internet IP ranges, with targeting weighted toward U.S. military-associated networks |
| Reconnaissance | T1595.002 | Active Scanning: Vulnerability Scanning | JDY scans for newly disclosed CVEs, with ability to begin scanning within hours of public vulnerability disclosure |
| Reconnaissance | T1590.005 | Gather Victim Network Information: Network Topology | JDY collects service banners, TLS certificate details, protocol metadata, and service fingerprints from scanned hosts, building a structured reconnaissance dataset for operators |
| Defense Evasion | T1090.003 | Proxy: Multi-hop Proxy | C2 operator communications are routed through Tor hidden services; compromised SOHO devices provide another layer of attribution obfuscation, consistent with Volt Typhoon's ORB (Operational Relay Box) network doctrine |
| Initial Access | T1190 | Exploit Public-Facing Application | JDY's scanning output feeds downstream exploitation of discovered vulnerabilities in internet-facing systems |

---

## 3. Malware & Tools

| Name | Type | Description |
|------|------|-------------|
| JDY Botnet Agent | Botnet malware (MIPS/MIPSEL variants) | Lightweight distributed scanner deployed on compromised SOHO/IoT devices; receives scan tasks from centralized C2 Dispatch Service; performs TCP/UDP/SSL/ICMP probing; captures banners, TLS certificates, and protocol fingerprints; reports structured results back to C2 for aggregation |

---

## 4. Threat Actor / Campaign Attribution

| Attribute | Detail |
|-----------|--------|
| Attribution | Volt Typhoon (China-nexus, PRC state-sponsored) |
| Attribution Confidence | Moderate-high (consistent infrastructure and behavioral overlap with prior KV-botnet/JDY tracking; Lumen Black Lotus Labs has monitored JDY continuously since 2022) |
| Campaign Name | JDY Botnet (sub-cluster of KV-botnet ecosystem) |
| Botnet Scale | 1,500+ active bots (June 2026); up from ~650 in January 2024 |
| Geographic Distribution | Majority in United States and Brazil; additional nodes in Europe and Asia |
| Primary Target | U.S. military networks and associated entities (most scanned IP blocks) |
| Secondary Targets | Critical infrastructure, SOHO appliances globally |
| Operational Purpose | Reconnaissance and target profiling; rapid CVE vulnerability scanning; attribution obfuscation layer for downstream Volt Typhoon intrusion operations |
| C2 Architecture | Centralized Dispatch Service accessible via Tor hidden services; layered operator access through Tor nodes |
| Scan Speed | Capable of shifting to newly disclosed CVEs within hours of public announcement |

---

## 5. Splunk Detection Searches

```spl
| comment "JDY botnet behavior: High-rate outbound TCP scan traffic from SOHO/edge device segment — anomalous scanning volume indicator"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime sum(All_Traffic.bytes_out) as total_bytes
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.src_category="edge" OR All_Traffic.src_category="iot" OR All_Traffic.src_category="firewall"
  by All_Traffic.src All_Traffic.dest_port All_Traffic.protocol
  | `drop_dm_object_name(All_Traffic)`
  | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)`
  | eval connections_per_dest=count
  | where connections_per_dest > 500
  | eval risk_score=case(
      connections_per_dest > 5000, 90,
      connections_per_dest > 1000, 80,
      1=1, 70)
  | where risk_score >= 70
  | table firstTime lastTime src dest_port protocol connections_per_dest total_bytes risk_score
```

```spl
| comment "JDY botnet: SOHO device communicating outbound over Tor-default ports (9001, 9030, 9050, 9051) — C2 operator channel indicator"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_port IN (9001,9030,9050,9051)
    AND (All_Traffic.src_category="edge" OR All_Traffic.src_category="iot"
         OR All_Traffic.src_category="firewall" OR All_Traffic.src_category="network_device")
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| where risk_score >= 85
| table firstTime lastTime src dest dest_port app risk_score
```

```spl
| comment "JDY botnet: Rapid fan-out scanning — single source scanning >50 unique destination IPs on same port within 5-minute window"
| tstats `security_content_summariesonly` dc(All_Traffic.dest) as unique_dests count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  by All_Traffic.src All_Traffic.dest_port _time span=5m
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| where unique_dests > 50
| eval risk_score=case(
    unique_dests > 500, 90,
    unique_dests > 100, 80,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime src dest_port unique_dests count risk_score
```

---

## 6. Executive Summary

The **JDY botnet** is a China-state-linked (Volt Typhoon) infrastructure of 1,500+ compromised SOHO routers, IoT devices, and access points used as a high-performance distributed scanning and reconnaissance platform. Black Lotus Labs' June 2026 research confirms that JDY has more than doubled in size since 2024 and has shifted toward aggressive targeting of U.S. military-associated networks, while maintaining the Tor-based C2 architecture and MIPS/MIPSEL botnet agent profile consistent with prior Volt Typhoon infrastructure.

What distinguishes JDY from typical botnets is its operational speed: Lumen observed JDY scanning for FortiClient EMS CVE-2026-35616 within hours of the public disclosure, indicating either automated CVE-to-scan pipeline capability or dedicated operators acting immediately upon vulnerability announcements. This behavior makes JDY a leading indicator for which newly disclosed vulnerabilities Volt Typhoon intends to exploit in downstream intrusion operations.

Defenders should:
1. Immediately isolate any SOHO appliance from Cisco, Araknis, Mimosa, Ubiquiti, DrayTek, Hikvision, or Linksys exhibiting anomalous outbound scanning behavior.
2. Monitor edge device segments for Tor port traffic (9001, 9030, 9050, 9051).
3. Patch FortiClient EMS, Cisco, and any recently disclosed SOHO/edge CVEs immediately — JDY scanning activity predicts exploitation attempts within days.
4. Obtain and block the JDY botnet IOC list from Lumen Black Lotus Labs' GitHub (link in References).

---

## References

- [Lumen Black Lotus Labs — Expanded JDY IoT and SOHO botnet enables rapid vulnerability exploitation](https://www.lumen.com/blog/en-us/expanded-jdy-iot-and-soho-botnet-enables-rapid-vulnerability-exploitation)
- [The Hacker News — China-Linked JDY Botnet Expands to 1,500+ Devices for Cyber Reconnaissance](https://thehackernews.com/2026/06/china-linked-jdy-botnet-expands-to-1500.html)
- [BleepingComputer — China-linked JDY botnet expands targeting of U.S. military networks](https://www.bleepingcomputer.com/news/security/china-linked-jdy-botnet-expands-targeting-of-us-military-networks/)
- [The Register — Chinese agents caught rebuilding botnets and stirring the pot on AI datacenter debate](https://www.theregister.com/security/2026/06/11/china-linked-operators-revive-botnet-stir-ai-datacenter-debate/)
- [Lumen Black Lotus Labs GitHub — JDY IOCs (continuously updated)](https://github.com/BlackLotusLabs)
- [MITRE ATT&CK — Volt Typhoon (G1017)](https://attack.mitre.org/groups/G1017/)
- [MITRE ATT&CK — T1595: Active Scanning](https://attack.mitre.org/techniques/T1595/)
- [CISA Advisory AA24-038A — PRC State-Sponsored Actors Compromise U.S. Critical Infrastructure](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a)
