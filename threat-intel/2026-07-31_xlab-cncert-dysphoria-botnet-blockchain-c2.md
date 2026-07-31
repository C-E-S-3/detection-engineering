---
scraped_at: "2026-07-31T08:00:00Z"
source_url: https://blog.xlab.qianxin.com/botnet-rising-star-the-evolution-and-in-depth-technical-analysis-of-dysphoria/
report_type: threat-intel
severity: high
title: "Dysphoria IoT Botnet — 200K Devices, Blockchain ENS/Solana C2, 4 Tbps DDoS, CVE-2025-55182/28137/9528"
---

# Dysphoria IoT Botnet — 200K Devices, Blockchain ENS/Solana C2, 4 Tbps DDoS

QiAnXin XLab, jointly with China's CNCERT, disclosed the Dysphoria botnet on July 29, 2026. The botnet has infected approximately 200,000 devices worldwide, uses Ethereum and Solana blockchain domains to hide C2 infrastructure (making seizure extremely difficult), and is a commercial DDoS-for-hire service claiming 4 Tbps capacity. Evolved from the jackskid and fbot malware families.

## 1. IOCs

### Blockchain C2 Domains
| Indicator | Type | Protocol | Notes |
|-----------|------|----------|-------|
| `burrberry.eth` | ENS domain | Ethereum Name Service | C2 relay node address lookup |
| `ukranianhorseriding.eth` | ENS domain | Ethereum Name Service | C2 relay node address lookup |
| `24carnforth2merseyside.sol` | SNS domain | Solana Name Service | C2 relay node address lookup |

### C2 IP (Decoded)
| IP | Source | Notes |
|----|--------|-------|
| `144.31.38.215` | XLab analysis | Decoded from ENS TXT record `12e7:13d7`; this is a relay node running on a victim host, not dedicated infrastructure |

### C2 Resolution Mechanism
Infected devices query ENS/SNS TXT records → receive fake IPv6 strings → apply custom byte-transformation (bit rotation + XOR against fixed key) → recover real IPv4 relay node address. Relay nodes are other compromised hosts, not attacker-controlled servers.

## 2. Campaign Scale

| Metric | Value | Period |
|--------|-------|--------|
| Total infected devices | ~200,000 | As of July 29, 2026 |
| Peak daily C2 sessions | 740,000 | July 14-20, 2026 |
| Peak overseas active nodes | 239,000/day | July 14-20, 2026 |
| Peak Chinese nodes | 1,801/day | July 14-20, 2026 |
| Claimed DDoS capacity | 4 Tbps | Operator advertisement |
| Tracking started | Q1 2026 | XLab first capture |

## 3. Malware Lineage and Variants

| Variant | First Seen | Key Behavior |
|---------|-----------|--------------|
| jackskid-based | March 25, 2026 | DDoS |
| fbot-based | April 1, 2026 | DDoS + blockchain C2 |
| Proxy-only variant | Late June 2026 | No DDoS; creates 155 UPnP port forwarding rules to expose internal services |

### String Encryption
- Custom RC4 implementation
- Key-scheduling: Linear Congruent Generator (LCG) layered into standard RC4 KSA
- Stream generation: Linear Feedback Shift Register (LFSR) layered into RC4 PRGA
- Purpose: Obfuscation of embedded C2 strings

### C2 Protocol
- Infected bots send fixed 78-byte login/heartbeat packet to C2
- C2 sends DDoS commands containing: duration, type, target(s), configurable flags
- DDoS variant issues HTTP GET to relay distribution nodes to retrieve current active relay list

## 4. CVEs Exploited

| CVE | Product | Affected Versions | Vuln Type |
|-----|---------|------------------|-----------|
| CVE-2025-55182 | React Server Components ("React2Shell") | 19.0.0–19.2.0 | Unauthenticated RCE; Flight protocol HTTP POST deserialization |
| CVE-2025-34152 | Unknown IoT device | — | RCE |
| CVE-2025-28137 | TOTOLINK A810R | V4.1.2cu.5182_B20201026 | Pre-auth RCE via `setNoticeCfg` / `NoticeUrl` parameter |
| CVE-2025-9528 | Linksys E1700 | 1.0.0.4.003 | OS command injection via `/goform/systemCommand` |
| CVE-2017-17215 | Huawei routers | Multiple | Legacy RCE (unpatched on many devices in the wild) |
| CVE-2020-8515 | DrayTek routers | Multiple | Legacy RCE (unpatched on many devices in the wild) |

Also propagates via weak Telnet and SSH credentials.

## 5. Target Device Types
- SOHO routers (Huawei, DrayTek, TOTOLINK, Linksys)
- IP cameras
- Network gateways
- Any embedded Linux device with Telnet/SSH exposure

## 6. TTPs

| Tactic | Technique ID | Technique |
|--------|-------------|-----------|
| Initial Access | T1110.001 | Brute Force: Password Guessing (Telnet/SSH) |
| Initial Access | T1190 | Exploit Public-Facing Application (CVE-2025-55182 et al.) |
| Command and Control | T1102.003 | Web Service: One-Way Communication (blockchain dead drop) |
| Command and Control | T1571 | Non-Standard Port |
| Impact | T1498 | Network Denial of Service |

## 7. Commercial DDoS-for-Hire
- Operators advertise services on clearnet
- Attack packages range from tens to hundreds of dollars
- Tiered by duration and bandwidth
- 4 Tbps claimed peak capacity

## 8. References

- [XLab — Botnet Rising Star: Dysphoria Technical Analysis](https://blog.xlab.qianxin.com/botnet-rising-star-the-evolution-and-in-depth-technical-analysis-of-dysphoria/)
- [BleepingComputer — New Dysphoria DDoS botnet spreads to 200k devices worldwide](https://www.bleepingcomputer.com/news/security/new-dysphoria-ddos-botnet-spreads-to-200k-devices-worldwide/)
- [The Hacker News — Dysphoria IoT Botnet Adds Blockchain C2 and Victim Relays After JackSkid Disruption](https://thehackernews.com/2026/07/dysphoria-iot-botnet-adds-blockchain-c2.html)
- [IOTNews — Dysphoria IoT botnet uses blockchain domains to hide 200k bots](https://iottechnews.com/news/dysphoria-iot-botnet-uses-blockchain-domains-to-hide-200k-bots/)
