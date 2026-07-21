---
scraped_at: 2026-07-16T00:00:00Z
source_url: https://unit42.paloaltonetworks.com/tuxbot-v3-evolution-iot-botnet/
report_type: threat-intel
severity: high
title: "TuxBot v3: LLM-Assisted Modular IoT Botnet with Multi-Protocol C2 and SHA512 DGA"
---

## 1. IOCs

### IP Addresses

| Indicator | Type | Description |
|-----------|------|-------------|
| `209.182.237[.]133` | IP (C2) | TuxBot v3 primary C2 server; Singapore-geolocated; TCP 2222; SSH banner `SSH-2.0-CNC-Control-Server`; first seen March 5, 2026 |
| `185.10.68[.]127` | IP (shared infra) | Shared infrastructure overlap with Keksec/Kaitori IoT botnet ecosystem; flagged malicious May 2026; likely TuxBot staging or relay node |

### Domains

| Indicator | Type | Description |
|-----------|------|-------------|
| `digikalas[.]online` | Domain | TuxBot developer infrastructure; leaked via Git log in a TuxBot v3 sample; hosted on Iran's Arvan Cloud CDN; suggests Iranian-nexus developer |

---

## 2. MITRE ATT&CK

| Field | Value |
|-------|-------|
| Tactic (Primary) | Command and Control (TA0011) |
| Technique | Encrypted Channel (T1573), Application Layer Protocol (T1071) |
| Additional Tactics | Impact (TA0040), Resource Development (TA0042) |
| Additional Techniques | Domain Generation Algorithms (T1568.002), Resource Hijacking — Cryptomining (T1496), Network Denial of Service (T1498) |
| Platform | Linux (embedded/IoT: ARM, MIPS, MIPSEL, MIPS64, x86_64, PowerPC, RISC-V, and 10+ others) |

---

## 3. Summary

**TuxBot v3** is a previously undocumented modular IoT botnet framework analyzed by Unit 42 and published July 15–16, 2026. It is notable for two reasons: (1) portions of its codebase show evidence of **LLM-assisted generation** (unusual code structure and commenting style inconsistent with human authorship), and (2) it implements an unusually sophisticated multi-protocol C2 architecture for an IoT botnet.

### LLM-Assisted Development

Unit 42 assessed that TuxBot v3 code shows evidence of AI-generated components. Specific sections contain verbose inline comments in non-native English and algorithmic patterns (particularly in the SHA512 DGA implementation) that are inconsistent with typical human IoT malware authors. This is the first IoT botnet where LLM assistance is assessed with meaningful confidence by a major threat intelligence team.

### Capabilities

| Capability | Detail |
|------------|--------|
| **DDoS** | Standard IoT botnet DDoS functionality |
| **Cryptocurrency mining** | Embedded miner (XMR/other); compiled with GCC 14.2.0 |
| **C2 protocols** | Encrypted TCP, SHA512 DGA, P2P gossip (Ed25519-signed), IRC, DNS TXT polling, HTTP polling |
| **Architecture support** | 17 CPU architectures: ARM, MIPS, MIPSEL, MIPS64, x86_64, PowerPC, RISC-V, and others |

### C2 Infrastructure

The primary C2 server at `209.182.237[.]133` (Singapore) listens on **TCP 2222** and presents an SSH banner of `SSH-2.0-CNC-Control-Server` — a non-standard banner that can serve as a network IOC.

TuxBot v3 also implements a **SHA512-seeded DGA** for backup C2 domain resolution and a **P2P gossip protocol** with Ed25519-signed messages to maintain botnet cohesion even if the primary C2 is sinkholed.

### Attribution

Unit 42 assesses **Iranian-nexus** attribution with moderate confidence based on:
- Developer domain `digikalas[.]online` hosted on Iran's Arvan Cloud CDN
- Infrastructure and tooling overlap with the **Keksec** / **Kaitori** IoT botnet ecosystem
- IP `185.10.68[.]127` shared with Keksec infrastructure, flagged malicious May 2026

### Discovery Timeline

| Date | Event |
|------|-------|
| January 20, 2026 | First VirusTotal submission of TuxBot v3 sample |
| March 5, 2026 | Primary C2 IP `209.182.237[.]133` first observed |
| April 2026 | Unit 42 telemetry identifies 6 TuxBot v3 samples |
| May 2026 | `185.10.68[.]127` flagged as malicious (Keksec overlap) |
| July 15–16, 2026 | Unit 42 public disclosure |

---

## 4. Detection Notes

- **Network signature**: TCP connections to port 2222 on external hosts with SSH banner `SSH-2.0-CNC-Control-Server` are highly specific IoT botnet C2 indicators. This banner is non-standard and unlikely to appear in legitimate SSH infrastructure.
- **DNS TXT polling**: TuxBot's DNS TXT-based C2 channel can be detected via high-frequency DNS TXT queries from IoT/embedded devices to domains with high-entropy labels.
- **Block IOC IPs**: Add `209.182.237[.]133` and `185.10.68[.]127` to threat intelligence feeds and firewall blocklists.
- **Port 2222 egress**: Unusual for legitimate IoT device to initiate outbound TCP 2222. Alert on outbound TCP 2222 from IoT VLAN segments to external addresses.

---

## 5. References

- Unit 42 (2026-07-15): https://unit42.paloaltonetworks.com/tuxbot-v3-evolution-iot-botnet/
- MITRE ATT&CK T1568.002 — Domain Generation Algorithms: https://attack.mitre.org/techniques/T1568/002/
- MITRE ATT&CK T1496 — Resource Hijacking: https://attack.mitre.org/techniques/T1496/
- Keksec botnet tracking: https://attack.mitre.org/groups/G0116/
